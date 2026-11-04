#if !defined(__APPLE__)
#error This diagnostic requires macOS.
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <pthread/qos.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#include "wait_snapshot.h"

#define PC_MAGIC WAIT_MAGIC
enum { PC_CPUS = 4, PC_PAGE_BYTES = 4096, PC_INTERVAL_MS = 100 };

struct pc_sample {
  uint64_t seq_before, timestamp_ns, kernel_pc, user_pc, pid, tid, cpu, seq_after;
};

struct wait_sample {
  uint64_t seq_before, zero_bits;
#define WAIT_MEMBER(context, name, index) uint64_t name;
  WAIT_FIELD_LIST(WAIT_MEMBER, unused)
#undef WAIT_MEMBER
  uint64_t seq_after, invalid_count, error_seen, cpu;
};

struct reader_state {
  uint64_t pc_sequence[PC_CPUS], wait_sequence[PC_CPUS];
  uint64_t invalid_count[PC_CPUS];
  bool error_seen;
};

struct pc_page {
  uint64_t magic, export_timestamp_ns, out_of_range_cpu, reserved;
  struct pc_sample samples[PC_CPUS];
  struct wait_sample waits[PC_CPUS];
};

_Static_assert(sizeof(struct pc_sample) == 64, "DTrace sample ABI");
_Static_assert(offsetof(struct pc_sample, seq_after) == 56, "DTrace sequence ABI");
_Static_assert(offsetof(struct pc_page, samples) == 32, "DTrace page header ABI");
_Static_assert(offsetof(struct pc_page, waits) == WAIT_PAGE_OFFSET,
               "DTrace wait page ABI");
_Static_assert(sizeof(struct wait_sample) == WAIT_SLOT_BYTES, "wait slot ABI");
#define WAIT_OFFSET(context, name, index) \
  _Static_assert(offsetof(struct wait_sample, name) == (2 + index) * 8, \
                 "wait field ABI: " #name);
WAIT_FIELD_LIST(WAIT_OFFSET, unused)
#undef WAIT_OFFSET
_Static_assert(offsetof(struct wait_sample, seq_after) ==
                   (2 + WAIT_FIELD_COUNT) * 8, "wait sequence ABI");
_Static_assert(offsetof(struct wait_sample, invalid_count) ==
                   (3 + WAIT_FIELD_COUNT) * 8, "wait counter ABI");
_Static_assert(offsetof(struct wait_sample, error_seen) ==
                   (4 + WAIT_FIELD_COUNT) * 8, "wait error ABI");
_Static_assert(offsetof(struct wait_sample, cpu) ==
                   (5 + WAIT_FIELD_COUNT) * 8, "wait CPU ABI");
_Static_assert(sizeof(struct pc_page) <= PC_PAGE_BYTES, "page capacity");

static volatile sig_atomic_t stopping;

static void stop_requested(int signo) {
  (void)signo;
  stopping = 1;
}

static uint64_t monotonic_ns(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static bool ticks_to_ns(uint64_t ticks,
                        const mach_timebase_info_data_t *timebase,
                        uint64_t *ns) {
  if (timebase->numer == 0 || timebase->denom == 0)
    return false;
  __uint128_t scaled = (__uint128_t)ticks * timebase->numer / timebase->denom;
  if (scaled > UINT64_MAX)
    return false;
  *ns = (uint64_t)scaled;
  return true;
}

static bool write_bracket_valid(uint64_t before, uint64_t after) {
  return before != 0 && after >= before;
}

static bool parse_milliseconds(const char *text, unsigned long maximum,
                               unsigned long *value) {
  char *end = NULL;
  errno = 0;
  unsigned long parsed = strtoul(text, &end, 10);
  if (text[0] == '-' || errno != 0 || end == text || *end != '\0' ||
      parsed < 1 || parsed > maximum)
    return false;
  *value = parsed;
  return true;
}

static bool coherent(const struct pc_sample *sample, unsigned cpu,
                     uint64_t export_timestamp_ns) {
  return sample->seq_before >= 2 && !(sample->seq_before & 1) &&
         sample->seq_before == sample->seq_after && sample->cpu == cpu &&
         sample->timestamp_ns <= export_timestamp_ns;
}

static uint64_t skipped(uint64_t previous, uint64_t current) {
  uint64_t base = previous == 0 ? 2 : previous;
  return current > base ? (current - base) / 2 - 1 : 0;
}

static const char *pc_kind(const struct pc_sample *sample) {
  if (sample->seq_before == 2)
    return "not_sampled";
  if (sample->kernel_pc == UINT64_C(0xcafebabe))
    return "unavailable";
  if (sample->kernel_pc != 0 && sample->user_pc == 0)
    return "kernel_interrupt_pc";
  if (sample->kernel_pc == 0 && sample->user_pc != 0)
    return "user_interrupt_pc";
  return "unavailable";
}

static bool decode_wait(const struct wait_sample *raw, struct wait_sample *out,
                        unsigned cpu) {
  if (raw->seq_before < 2 || (raw->seq_before & 1) ||
      raw->seq_before != raw->seq_after || raw->cpu != cpu ||
      (raw->zero_bits & ~WAIT_ZERO_MASK) != 0)
    return false;
  *out = *raw;
#define WAIT_DECODE(context, name, index) \
  if (raw->name == 0 || ((raw->zero_bits & (UINT64_C(1) << index)) && \
                        raw->name != 1)) \
    return false; \
  out->name = (raw->zero_bits & (UINT64_C(1) << index)) ? 0 : raw->name;
  WAIT_FIELD_LIST(WAIT_DECODE, unused)
#undef WAIT_DECODE
  if (raw->seq_before == 2 && raw->zero_bits != WAIT_ZERO_MASK)
    return false;
  return true;
}

static bool wait_facts_valid(const struct wait_sample *wait,
                             const struct pc_sample *pc,
                             uint64_t export_timestamp_ns) {
  if (wait->seq_before == 2)
    return true;
  if (wait->sample_timestamp_ns == 0 ||
      wait->sample_timestamp_ns > export_timestamp_ns ||
      wait->profile_generation < 4 || (wait->profile_generation & 1) ||
      wait->profile_generation > pc->seq_before ||
      wait->slide > UINT64_MAX - UINT64_C(0xffffff80003f91c9) ||
      !WAIT_SAFE_PC(wait->rip, wait->slide) || wait->frame == 0 || wait->cs != 8)
    return false;
  if (wait->profile_generation == pc->seq_before &&
      (wait->sample_timestamp_ns < pc->timestamp_ns || wait->pid != pc->pid ||
       wait->tid != pc->tid || wait->rip != pc->kernel_pc || pc->user_pc != 0))
    return false;
  if (wait->profile_generation < pc->seq_before &&
      wait->sample_timestamp_ns > pc->timestamp_ns)
    return false;
  if (wait->base == 0 || wait->top <= wait->base ||
      wait->top - wait->base != 16384 || (wait->rbp & 7) ||
      wait->rbp < wait->base + 0x30 || wait->rbp > wait->top - 0x10 ||
      wait->rsp != wait->rbp - 0x30 || (wait->parent & 7) ||
      wait->parent < wait->base + 0x78 || wait->parent > wait->top - 0x10 ||
      wait->parent <= wait->rbp || wait->parent - wait->rbp != 0xc0 ||
      wait->rbx != wait->parent - 0x70)
    return false;
  bool mode_return =
      (wait->mode == 0 && wait->return_pc == wait->slide + WAIT_UNSLID_SYNC_RETURN) ||
      (wait->mode == 1 && wait->return_pc == wait->slide + WAIT_UNSLID_ASYNC_RETURN);
  return mode_return && wait->called == wait->parent_called &&
         (wait->called & ~wait->requested) == 0 && (wait->called & ~15ULL) == 0 &&
         (wait->response_before & ~wait->called) == 0 &&
         (wait->response_after & ~wait->called) == 0 &&
         (wait->response_before & ~wait->response_after) == 0;
}

static bool wait_regressed(uint64_t previous, uint64_t current) {
  return previous > current;
}

static int emit_waits(const struct pc_page *page, struct reader_state *state,
                      const bool pc_accepted[PC_CPUS], bool armed) {
  for (unsigned cpu = 0; cpu < PC_CPUS; ++cpu)
    if (armed && page->waits[cpu].error_seen != 0)
      state->error_seen = true;
  if (printf("],\"wait_observer_error_seen\":%s,\"waits\":[",
             state->error_seen ? "true" : "false") < 0)
    return 74;
  for (unsigned cpu = 0; cpu < PC_CPUS; ++cpu) {
    const struct wait_sample *raw = &page->waits[cpu];
    const struct pc_sample *pc = &page->samples[cpu];
    struct wait_sample wait = {0};
    bool counters = armed && pc_accepted[cpu] && raw->cpu == cpu &&
                    raw->error_seen <= 1 &&
                    raw->invalid_count <= (pc->seq_before - 2) / 2 &&
                    raw->invalid_count >= state->invalid_count[cpu];
    bool transport = armed && decode_wait(raw, &wait, cpu);
    bool regression = transport &&
                      wait_regressed(state->wait_sequence[cpu], wait.seq_before);
    bool accepted = transport && !regression && counters &&
                    wait_facts_valid(&wait, pc, page->export_timestamp_ns);
    bool captured = accepted && wait.seq_before > 2;
    if (printf("%s{\"cpu\":%u,\"coherent\":%s,\"trustworthy\":%s,"
               "\"sequence_regressed\":%s,\"seq_before\":%" PRIu64
               ",\"seq_after\":%" PRIu64 ",\"counter_transport_valid\":%s,"
               "\"invalid_count\":%" PRIu64 ",\"error_seen\":%" PRIu64
               ",\"captured\":%s",
               cpu == 0 ? "" : ",", cpu, accepted ? "true" : "false",
               accepted && !state->error_seen ? "true" : "false",
               regression ? "true" : "false", raw->seq_before, raw->seq_after,
               counters ? "true" : "false", raw->invalid_count, raw->error_seen,
               captured ? "true" : "false") < 0)
      return 74;
    if (captured) {
      if (printf(",\"record_kind\":\"latched_wait_sample\","
                 "\"current_profile_generation\":%" PRIu64
                 ",\"latest_profile_is_wait_sample\":%s,"
                 "\"age_at_export_ns\":%" PRIu64
                 ",\"response_stable\":%s,\"pending_before\":%" PRIu64
                 ",\"pending_after\":%" PRIu64,
                 pc->seq_before,
                 wait.profile_generation == pc->seq_before ? "true" : "false",
                 page->export_timestamp_ns - wait.sample_timestamp_ns,
                 wait.response_before == wait.response_after ? "true" : "false",
                 wait.called & ~wait.response_before,
                 wait.called & ~wait.response_after) < 0)
        return 74;
#define WAIT_PRINT(context, name, index) \
      if (printf(",\"" #name "\":%" PRIu64, wait.name) < 0) return 74;
      WAIT_FIELD_LIST(WAIT_PRINT, unused)
#undef WAIT_PRINT
    }
    if (accepted)
      state->wait_sequence[cpu] = wait.seq_before;
    if (counters)
      state->invalid_count[cpu] = raw->invalid_count;
    if (printf("}") < 0)
      return 74;
  }
  return printf("]}\n") < 0 || fflush(stdout) != 0 ? 74 : 0;
}

static int emit_snapshot(const struct pc_page *page, struct reader_state *state,
                         uint64_t snapshot, uint64_t mach_before_write_ns,
                         uint64_t mach_after_write_ns) {
  bool armed = page->magic == PC_MAGIC;
  bool pc_accepted[PC_CPUS] = {0};
  if (printf("{\"event\":\"pc_snapshot\",\"snapshot\":%" PRIu64
             ",\"observed_monotonic_ns\":%" PRIu64
             ",\"mach_before_write_ns\":%" PRIu64
             ",\"mach_after_write_ns\":%" PRIu64
             ",\"mach_write_bracket_valid\":%s"
             ",\"armed\":%s,\"complete_trace\":false,"
             "\"export_timestamp_ns\":%" PRIu64
             ",\"out_of_range_cpu\":%" PRIu64 ",\"cpus\":[",
             snapshot, monotonic_ns(), mach_before_write_ns, mach_after_write_ns,
             write_bracket_valid(mach_before_write_ns, mach_after_write_ns)
                 ? "true"
                 : "false",
             armed ? "true" : "false",
             page->export_timestamp_ns, page->out_of_range_cpu) < 0)
    return 74;
  for (unsigned cpu = 0; cpu < PC_CPUS; ++cpu) {
    const struct pc_sample *sample = &page->samples[cpu];
    bool stable = armed && coherent(sample, cpu, page->export_timestamp_ns);
    bool regression = stable && state->pc_sequence[cpu] > sample->seq_before;
    bool accepted = stable && !regression;
    pc_accepted[cpu] = accepted;
    bool changed = accepted && sample->seq_before != state->pc_sequence[cpu];
    uint64_t gap = accepted ? skipped(state->pc_sequence[cpu], sample->seq_before) : 0;
    if (printf("%s{\"cpu\":%u,\"coherent\":%s,\"sequence_regressed\":%s,"
               "\"seq_before\":%" PRIu64 ",\"seq_after\":%" PRIu64
               ",\"changed\":%s,\"seq_gap\":%" PRIu64,
               cpu == 0 ? "" : ",", cpu, accepted ? "true" : "false",
               regression ? "true" : "false", sample->seq_before,
               sample->seq_after, changed ? "true" : "false", gap) < 0)
      return 74;
    if (accepted) {
      if (printf(",\"sample_timestamp_ns\":%" PRIu64
                 ",\"age_at_export_ns\":%" PRIu64
                 ",\"pid\":%" PRIu64 ",\"tid\":%" PRIu64
                 ",\"kernel_pc\":\"0x%016" PRIx64
                 "\",\"user_pc\":\"0x%016" PRIx64
                 "\",\"pc_kind\":\"%s\"",
                 sample->timestamp_ns,
                 page->export_timestamp_ns - sample->timestamp_ns, sample->pid,
                 sample->tid, sample->kernel_pc, sample->user_pc,
                 pc_kind(sample)) < 0)
        return 74;
      state->pc_sequence[cpu] = sample->seq_before;
    }
    if (printf("}") < 0)
      return 74;
  }
  return emit_waits(page, state, pc_accepted, armed);
}

static struct wait_sample encode_wait_fixture(struct wait_sample wait) {
  wait.zero_bits = 0;
#define WAIT_ENCODE(context, name, index) \
  if (wait.name == 0) { \
    wait.zero_bits |= UINT64_C(1) << index; \
    wait.name = 1; \
  }
  WAIT_FIELD_LIST(WAIT_ENCODE, unused)
#undef WAIT_ENCODE
  return wait;
}

static int self_test(void) {
  uint64_t converted = 0;
  mach_timebase_info_data_t scale = {.numer = 125, .denom = 3};
  unsigned long parsed = 0;
  if (!ticks_to_ns(123, &scale, &converted) || converted != 5125 ||
      ticks_to_ns(UINT64_MAX, &scale, &converted) ||
      ticks_to_ns(1, &(mach_timebase_info_data_t){1, 0}, &converted) ||
      ticks_to_ns(1, &(mach_timebase_info_data_t){0, 1}, &converted) ||
      !write_bracket_valid(100000, 100010) ||
      !write_bracket_valid(100000, 100000) || write_bracket_valid(0, 10) ||
      write_bracket_valid(10, 9) ||
      !parse_milliseconds("1", 1000, &parsed) || parsed != 1 ||
      !parse_milliseconds("1000", 1000, &parsed) || parsed != 1000 ||
      parse_milliseconds("0", 1000, &parsed) ||
      parse_milliseconds("1001", 1000, &parsed) ||
      parse_milliseconds("10ms", 1000, &parsed))
    return 70;
  struct pc_page page = {.magic = PC_MAGIC, .export_timestamp_ns = 1000};
  struct reader_state state = {0};
  for (unsigned cpu = 0; cpu < PC_CPUS; ++cpu) {
    page.samples[cpu] = (struct pc_sample){.seq_before = 2,
                                          .cpu = cpu,
                                          .seq_after = 2};
    page.waits[cpu] = encode_wait_fixture((struct wait_sample){
        .seq_before = 2, .seq_after = 2, .cpu = cpu});
  }
  page.samples[0] = (struct pc_sample){4, 500, 0xffffff80003f91c2ULL,
                                      0, 17, 19, 0, 4};
  page.samples[1] = (struct pc_sample){10, 750, 0, 0x10001234, 23, 29, 1, 10};
  page.samples[2].seq_before = 5;
  page.samples[2].seq_after = 6;
  if (!coherent(&page.samples[0], 0, 1000) ||
      coherent(&page.samples[0], 1, 1000) ||
      coherent(&page.samples[0], 0, 499) ||
      coherent(&page.samples[2], 2, 1000) || skipped(0, 4) != 0 ||
      skipped(0, 10) != 3 || skipped(4, 10) != 2 || skipped(4, 4) != 0 ||
      strcmp(pc_kind(&page.samples[0]), "kernel_interrupt_pc") != 0 ||
      strcmp(pc_kind(&page.samples[1]), "user_interrupt_pc") != 0)
    return 70;
  struct wait_sample expected = {
      .seq_before = 4, .seq_after = 4, .cpu = 0,
      .sample_timestamp_ns = 510, .profile_generation = 4, .pid = 17, .tid = 19,
      .rip = UINT64_C(0xffffff80003f91c2),
      .base = UINT64_C(0xffffff9000000000),
      .top = UINT64_C(0xffffff9000004000),
      .parent = UINT64_C(0xffffff9000001000),
      .rbp = UINT64_C(0xffffff9000000f40),
      .rbx = UINT64_C(0xffffff9000000f90),
      .rsp = UINT64_C(0xffffff9000000f10), .cs = 8, .rflags = 0x202,
      .frame = UINT64_C(0xffffff9000002000),
      .return_pc = WAIT_UNSLID_ASYNC_RETURN, .mode = 1,
      .requested = UINT64_MAX, .called = 6, .parent_called = 6,
      .response_before = 2, .response_after = 6,
      .action = UINT64_MAX, .action_arg0 = 0, .action_arg1 = UINT64_MAX};
  page.waits[0] = encode_wait_fixture(expected);
  struct wait_sample decoded;
  if (!decode_wait(&page.waits[0], &decoded, 0) ||
      decoded.requested != UINT64_MAX || decoded.action != UINT64_MAX ||
      decoded.action_arg0 != 0 || decoded.action_arg1 != UINT64_MAX ||
      !wait_facts_valid(&decoded, &page.samples[0], 1000) ||
      wait_facts_valid(&decoded, &page.samples[0], 499) ||
      !wait_regressed(6, 4) || wait_regressed(4, 4) || wait_regressed(4, 6))
    return 70;
  struct wait_sample bad = page.waits[0];
  bad.seq_before = 5;
  if (decode_wait(&bad, &decoded, 0)) return 70;
  bad = page.waits[0];
  bad.seq_after = 6;
  if (decode_wait(&bad, &decoded, 0) || decode_wait(&page.waits[0], &decoded, 1))
    return 70;
  bad = page.waits[0];
  bad.action_arg0 = 0;
  if (decode_wait(&bad, &decoded, 0)) return 70;
  bad = page.waits[0];
  bad.zero_bits |= UINT64_C(1) << WAIT_FIELD_COUNT;
  if (decode_wait(&bad, &decoded, 0)) return 70;
  bad = expected;
  bad.parent++;
  if (wait_facts_valid(&bad, &page.samples[0], 1000)) return 70;
  bad = expected;
  bad.response_after = 16;
  if (wait_facts_valid(&bad, &page.samples[0], 1000)) return 70;
  bad = expected;
  bad.response_after = 0;
  if (wait_facts_valid(&bad, &page.samples[0], 1000)) return 70;
  bad = expected;
  bad.profile_generation = 6;
  if (wait_facts_valid(&bad, &page.samples[0], 1000)) return 70;
  bad = expected;
  bad.mode = 0;
  if (wait_facts_valid(&bad, &page.samples[0], 1000)) return 70;
  bad = expected;
  bad.sample_timestamp_ns = 499;
  if (wait_facts_valid(&bad, &page.samples[0], 1000)) return 70;
  struct pc_sample later_pc = page.samples[0];
  later_pc.seq_before = later_pc.seq_after = 6;
  later_pc.timestamp_ns = 600;
  later_pc.kernel_pc = 0;
  later_pc.user_pc = 0x10001234;
  if (!wait_facts_valid(&expected, &later_pc, 1000)) return 70;
  bad = expected;
  bad.sample_timestamp_ns = 601;
  if (wait_facts_valid(&bad, &later_pc, 1000)) return 70;
  if (!decode_wait(&page.waits[3], &decoded, 3) || decoded.rip != 0 ||
      !wait_facts_valid(&decoded, &page.samples[3], 1000)) return 70;
  return emit_snapshot(&page, &state, 1, 100000, 100010);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
    return self_test();
#if !defined(__x86_64__)
  fprintf(stderr, "live sampling requires Intel x86_64\n");
  return 77;
#endif
  unsigned long duration_ms = 0, interval_ms = PC_INTERVAL_MS;
  if ((argc != 2 && argc != 3) ||
      !parse_milliseconds(argv[1], 900000, &duration_ms) ||
      (argc == 3 && !parse_milliseconds(argv[2], 1000, &interval_ms))) {
    fprintf(stderr, "usage: pc_sampler duration_ms (1..900000) "
                    "[interval_ms (1..1000)] | --self-test\n");
    return 64;
  }
  mach_timebase_info_data_t timebase;
  if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.numer == 0 ||
      timebase.denom == 0)
    return 71;
  if (interval_ms < PC_INTERVAL_MS) {
    int error = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    if (error != 0) {
      fprintf(stderr, "pthread_set_qos_class_self_np: %s\n", strerror(error));
      return 71;
    }
  }
  int maximum_cpus = 0;
  size_t size = sizeof(maximum_cpus);
  if (sysctlbyname("hw.logicalcpu_max", &maximum_cpus, &size, NULL, 0) != 0 ||
      size != sizeof(maximum_cpus) || maximum_cpus < 1 || maximum_cpus > PC_CPUS) {
    fprintf(stderr, "requires hw.logicalcpu_max in 1..4\n");
    return 77;
  }
  struct pc_page *page = mmap(NULL, PC_PAGE_BYTES, PROT_READ | PROT_WRITE,
                             MAP_ANON | MAP_PRIVATE, -1, 0);
  if (page == MAP_FAILED)
    return 71;
  memset(page, 0, PC_PAGE_BYTES);
  if (mlock(page, PC_PAGE_BYTES) != 0) {
    munmap(page, PC_PAGE_BYTES);
    return 77;
  }
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    munlock(page, PC_PAGE_BYTES);
    munmap(page, PC_PAGE_BYTES);
    return 71;
  }
  struct sigaction action = {.sa_handler = stop_requested};
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGINT, &action, NULL) != 0 ||
      sigaction(SIGTERM, &action, NULL) != 0) {
    close(fd);
    munlock(page, PC_PAGE_BYTES);
    munmap(page, PC_PAGE_BYTES);
    return 71;
  }
  setvbuf(stdout, NULL, _IOLBF, 0);
  int result = 0;
  if (printf("{\"event\":\"pc_sampler_buffer\",\"pid\":%ld,"
             "\"address\":%" PRIuPTR ",\"bytes\":%u,\"fd\":%d,"
             "\"cpu_slots\":%u,\"maximum_cpus\":%d,\"interval_ms\":%lu,"
             "\"duration_ms\":%lu,\"complete_trace\":false,"
             "\"abi_version\":2,\"wait_slots\":4,"
             "\"requested_qos\":\"%s\","
             "\"clock_sources\":{"
             "\"observed_monotonic_ns\":\"CLOCK_MONOTONIC\","
             "\"mach_before_write_ns\":\"mach_absolute_time*timebase\","
             "\"mach_after_write_ns\":\"mach_absolute_time*timebase\","
             "\"export_timestamp_ns\":\"DTrace timestamp\","
             "\"sample_timestamp_ns\":\"DTrace timestamp\","
             "\"wait_sample_timestamp_ns\":\"DTrace timestamp, cached within wait clause\"},"
             "\"mach_timebase_numer\":%u,\"mach_timebase_denom\":%u}\n",
             (long)getpid(), (uintptr_t)page, PC_PAGE_BYTES, fd, PC_CPUS,
             maximum_cpus, interval_ms, duration_ms,
             interval_ms < PC_INTERVAL_MS ? "user_interactive" : "unchanged",
             timebase.numer, timebase.denom) < 0 ||
      fflush(stdout) != 0)
    result = 74;
  struct reader_state state = {0};
  uint64_t started = monotonic_ns();
  if (started == 0)
    result = 71;
  uint64_t deadline = started + duration_ms * UINT64_C(1000000);
  uint64_t snapshot = 0;
  while (result == 0 && !stopping) {
    uint64_t now = monotonic_ns();
    if (now == 0) {
      result = 71;
      break;
    }
    if (now >= deadline)
      break;
    // Only this thread invokes the dedicated write. Its callback completes
    // before these ordinary user loads; profile never writes the user page.
    memset(page, 0, sizeof(*page));
    uint64_t mach_before_write_ns = 0, mach_after_write_ns = 0;
    if (!ticks_to_ns(mach_absolute_time(), &timebase, &mach_before_write_ns)) {
      result = 71;
      break;
    }
    ssize_t written = write(fd, page, 0);
    if (!ticks_to_ns(mach_absolute_time(), &timebase, &mach_after_write_ns) ||
        written != 0 ||
        !write_bracket_valid(mach_before_write_ns, mach_after_write_ns)) {
      result = 71;
      break;
    }
    // For armed exports, Mach - DTrace lies between before - export and
    // after - export. The syscall can be preempted, so retain both bounds.
    result = emit_snapshot(page, &state, ++snapshot, mach_before_write_ns,
                           mach_after_write_ns);
    if (page->magic == PC_MAGIC && page->out_of_range_cpu != 0)
      result = 77;
    struct timespec pause = {.tv_sec = (time_t)(interval_ms / 1000),
                             .tv_nsec = (long)(interval_ms % 1000) * 1000000L};
    while (!stopping && nanosleep(&pause, &pause) != 0) {
      if (errno != EINTR) {
        result = 71;
        break;
      }
    }
  }
  close(fd);
  munlock(page, PC_PAGE_BYTES);
  munmap(page, PC_PAGE_BYTES);
  return result;
}
