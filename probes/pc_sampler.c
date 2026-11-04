#if !defined(__APPLE__)
#error This diagnostic requires macOS.
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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

#define PC_MAGIC UINT64_C(0x504353414d504c31)
enum { PC_CPUS = 4, PC_PAGE_BYTES = 4096, PC_INTERVAL_MS = 100 };

struct pc_sample {
  uint64_t seq_before, timestamp_ns, kernel_pc, user_pc, pid, tid, cpu, seq_after;
};

struct pc_page {
  uint64_t magic, export_timestamp_ns, out_of_range_cpu, reserved;
  struct pc_sample samples[PC_CPUS];
};

_Static_assert(sizeof(struct pc_sample) == 64, "DTrace sample ABI");
_Static_assert(offsetof(struct pc_sample, seq_after) == 56, "DTrace sequence ABI");
_Static_assert(offsetof(struct pc_page, samples) == 32, "DTrace page header ABI");
_Static_assert(sizeof(struct pc_page) == 288, "DTrace page ABI");
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

static int emit_snapshot(const struct pc_page *page, uint64_t previous[PC_CPUS],
                         uint64_t snapshot) {
  bool armed = page->magic == PC_MAGIC;
  if (printf("{\"event\":\"pc_snapshot\",\"snapshot\":%" PRIu64
             ",\"observed_monotonic_ns\":%" PRIu64
             ",\"armed\":%s,\"complete_trace\":false,"
             "\"export_timestamp_ns\":%" PRIu64
             ",\"out_of_range_cpu\":%" PRIu64 ",\"cpus\":[",
             snapshot, monotonic_ns(), armed ? "true" : "false",
             page->export_timestamp_ns, page->out_of_range_cpu) < 0)
    return 74;
  for (unsigned cpu = 0; cpu < PC_CPUS; ++cpu) {
    const struct pc_sample *sample = &page->samples[cpu];
    bool stable = armed && coherent(sample, cpu, page->export_timestamp_ns);
    bool regression = stable && previous[cpu] > sample->seq_before;
    bool accepted = stable && !regression;
    bool changed = accepted && sample->seq_before != previous[cpu];
    uint64_t gap = accepted ? skipped(previous[cpu], sample->seq_before) : 0;
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
      previous[cpu] = sample->seq_before;
    }
    if (printf("}") < 0)
      return 74;
  }
  return printf("]}\n") < 0 || fflush(stdout) != 0 ? 74 : 0;
}

static int self_test(void) {
  struct pc_page page = {.magic = PC_MAGIC, .export_timestamp_ns = 1000};
  uint64_t previous[PC_CPUS] = {0};
  for (unsigned cpu = 0; cpu < PC_CPUS; ++cpu)
    page.samples[cpu] = (struct pc_sample){.seq_before = 2,
                                          .cpu = cpu,
                                          .seq_after = 2};
  page.samples[0] = (struct pc_sample){4, 500, 0xffffff8000001234ULL,
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
  return emit_snapshot(&page, previous, 1);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
    return self_test();
#if !defined(__x86_64__)
  fprintf(stderr, "live sampling requires Intel x86_64\n");
  return 77;
#endif
  char *end = NULL;
  errno = 0;
  unsigned long duration_ms = argc == 2 ? strtoul(argv[1], &end, 10) : 0;
  if (argc != 2 || errno != 0 || end == argv[1] || *end != '\0' ||
      duration_ms < 1 || duration_ms > 900000) {
    fprintf(stderr, "usage: pc_sampler duration_ms (1..900000) | --self-test\n");
    return 64;
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
             "\"cpu_slots\":%u,\"maximum_cpus\":%d,\"interval_ms\":%u,"
             "\"duration_ms\":%lu,\"complete_trace\":false}\n",
             (long)getpid(), (uintptr_t)page, PC_PAGE_BYTES, fd, PC_CPUS,
             maximum_cpus, PC_INTERVAL_MS, duration_ms) < 0 ||
      fflush(stdout) != 0)
    result = 74;
  uint64_t previous[PC_CPUS] = {0};
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
    if (write(fd, page, 0) != 0) {
      result = 71;
      break;
    }
    result = emit_snapshot(page, previous, ++snapshot);
    if (page->magic == PC_MAGIC && page->out_of_range_cpu != 0)
      result = 77;
    struct timespec pause = {.tv_nsec = PC_INTERVAL_MS * 1000000L};
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
