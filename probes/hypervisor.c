#if !defined(__x86_64__)
#error Build this probe only for x86_64.
#endif
#ifndef PROBE_SOURCE_SHA
#error Define PROBE_SOURCE_SHA as the SHA-256 of this source.
#endif

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

enum {
  PAGE_BYTES = 4096,
  PAGE_DIRECTORY = PAGE_BYTES,
  PAGE_TABLE = 2 * PAGE_BYTES,
  CODE = 0x100,
  GDT = 0x400,
  TSS = 0x500,
  SENTINEL = 0x800,
  TAG = 0xa5,
  KERNEL_MARKER_CAPACITY = 32
};

enum guest_mode { REAL16, PROTECTED32 };

struct guest_segment {
  uint64_t selector, base, limit, rights;
};

struct mode_profile {
  uint8_t mov[7];
  size_t mov_length;
  uint64_t cr0_set;
  struct guest_segment cs, data, tr, ldtr;
  uint64_t gdtr_base, gdtr_limit;
  uint8_t gdt[4][8], tss[104];
};

static const struct mode_profile profiles[] = {
    [REAL16] = {.mov = {0xc6, 0x06, 0x00, 0x08, TAG},
                .mov_length = 5,
                .cs = {.limit = 0xffff, .rights = 0x9b},
                .data = {.limit = 0xffff, .rights = 0x93},
                .tr = {.limit = 0xffff, .rights = 0x8b},
                .ldtr = {.limit = 0xffff, .rights = 0x10000},
                .gdtr_limit = 0xffff},
    [PROTECTED32] =
        {
            .mov = {0xc6, 0x05, 0x00, 0x08, 0x00, 0x00, TAG},
            .mov_length = 7,
            .cr0_set = 1,
            .cs = {.selector = 0x08, .limit = UINT32_MAX, .rights = 0xc09b},
            .data = {.selector = 0x10, .limit = UINT32_MAX, .rights = 0xc093},
            .tr = {.selector = 0x18, .base = TSS, .limit = 103, .rights = 0x8b},
            .ldtr = {.limit = 0xffff, .rights = 0x10000},
            .gdtr_base = GDT,
            .gdtr_limit = 31,
            // Null, ring-0 code/data and busy 32-bit TSS descriptors match the
            // cached segment state. SDM vol. 3A, 3.4.5 and 8.2; vol.
            // 3C, 27.3.1.2.
            .gdt = {{0},
                    {0xff, 0xff, 0, 0, 0, 0x9b, 0xcf, 0},
                    {0xff, 0xff, 0, 0, 0, 0x93, 0xcf, 0},
                    {0x67, 0, 0, 5, 0, 0x8b, 0, 0}},
            // ESP0=0xff0, SS0=0x10; the I/O bitmap starts beyond the TSS limit.
            .tss = {[4] = 0xf0, [5] = 0x0f, [8] = 0x10, [102] = 104},
        },
};

enum paging_kind { PAGING_LEGACY, PAGING_DISABLED, PAGING_ENABLED };

struct paging_profile {
  size_t memory_bytes;
  uint64_t cr0_set, cr3;
};

static const struct paging_profile paging_profiles[] = {
    [PAGING_LEGACY] = {.memory_bytes = PAGE_BYTES},
    [PAGING_DISABLED] = {.memory_bytes = 3 * PAGE_BYTES, .cr3 = PAGE_DIRECTORY},
    [PAGING_ENABLED] = {.memory_bytes = 3 * PAGE_BYTES,
                        .cr0_set = 1ULL << 31,
                        .cr3 = PAGE_DIRECTORY},
};

// SDM vol. 3A, 4.3: supervisor read/write 4KiB identity mappings, CR4.PAE=0.
static const uint32_t page_directory[] = {PAGE_TABLE | 3};
static const uint32_t page_table[] = {3, PAGE_DIRECTORY | 3, PAGE_TABLE | 3};

enum guest_kind {
  GUEST_HLT,
  GUEST_CPUID,
  GUEST_SPIN,
  GUEST_STI_HLT,
  GUEST_HLT_TIMER,
  GUEST_MTF_NOP
};
enum observer_kind {
  OBSERVER_NONE,
  OBSERVER_SENTINEL,
  OBSERVER_THREADINFO,
  OBSERVER_INTERRUPT,
  OBSERVER_KERNELMARKERS
};

struct guest_case {
  uint8_t tail[3];
  uint64_t exit_reason;
  // Zero means the asynchronous exit's instruction length is not read or gated.
  uint64_t instruction_length;
  uint64_t tail_offset, activity_state;
  const char *verified_fact;
};

// Intel SDM vol. 2 defines HLT, STI, NOP, CPUID and JMP encodings; vol. 3C
// appendix C defines HLT=12, CPUID=10 and VMX preemption timer=52 exit reasons.
static const struct guest_case guests[] = {
    [GUEST_HLT] = {.tail = {0xf4, 0x90},
                   .exit_reason = 12,
                   .instruction_length = 1,
                   .tail_offset = 0,
                   .verified_fact = "sentinel_hlt_verified"},
    [GUEST_CPUID] = {.tail = {0x0f, 0xa2},
                     .exit_reason = 10,
                     .instruction_length = 2,
                     .tail_offset = 0,
                     .verified_fact = "sentinel_cpuid_verified"},
    [GUEST_SPIN] = {.tail = {0xeb, 0xfe},
                    .exit_reason = 52,
                    .instruction_length = 0,
                    .tail_offset = 0,
                    .verified_fact = "sentinel_spin_verified"},
    [GUEST_STI_HLT] = {.tail = {0xfb, 0xf4},
                       .exit_reason = 12,
                       .instruction_length = 1,
                       .tail_offset = 1,
                       .verified_fact = "sentinel_sti_hlt_verified"},
    [GUEST_HLT_TIMER] = {.tail = {0xf4, 0x90},
                         .exit_reason = 52,
                         .instruction_length = 0,
                         .tail_offset = 1,
                         .activity_state = 1,
                         .verified_fact = "sentinel_hlt_timer_verified"},
    [GUEST_MTF_NOP] = {.tail = {0x90, 0x0f, 0x0b}},
};

struct kernel_marker_body {
  uint64_t timestamp_ns, caller_pc, arg0, arg1, tid, meta;
};

struct kernel_marker_slot {
  struct kernel_marker_body body;
  _Atomic uint64_t commit;
};

_Static_assert(sizeof(struct kernel_marker_body) == 48, "kernel marker body");
_Static_assert(offsetof(struct kernel_marker_slot, commit) == 48,
               "kernel marker commit offset");
_Static_assert(sizeof(struct kernel_marker_slot) == 56, "kernel marker slot");
_Static_assert(KERNEL_MARKER_CAPACITY * sizeof(struct kernel_marker_slot) <=
                   PAGE_BYTES,
               "kernel markers fit in one page");

struct phase_case {
  const char *name;
  enum guest_kind guest;
  enum guest_mode mode;
  enum paging_kind paging;
  enum observer_kind observer;
  hv_vm_options_t vm_flags;
  bool armed, control, forever, cr8_exits, timer_only;
  unsigned mtf_phase;
};

struct observer {
  mach_timebase_info_data_t timebase;
  const char *phase;
  const uint8_t *memory;
  hv_vcpuid_t vcpu;
  enum observer_kind kind;
  uint64_t owner_tid;
  const struct kernel_marker_slot *markers;
  const atomic_bool *stop;
};

struct probe {
  mach_timebase_info_data_t timebase;
  const char *phase;
  const struct guest_case *guest;
  const struct mode_profile *profile;
  const struct paging_profile *paging;
  uint64_t sequence;
  uint64_t cr0_fixed0, cr0_fixed1, cr4_fixed0, cr4_fixed1;
  hv_vcpuid_t vcpu;
  uint8_t *memory;
  struct observer observer;
  struct kernel_marker_slot *markers;
  atomic_bool observer_stop;
  bool marker_locked;
  bool vm_created, mapped, cpu_created, cleaning, output_failed, guest_verified;
  bool observer_active, cr8_exits, timer_only;
  unsigned mtf_phase;
};

static uint64_t observer_now(const struct observer *o) {
  return (uint64_t)((__uint128_t)mach_absolute_time() * o->timebase.numer /
                    o->timebase.denom);
}

static int observe_thread_info(const struct observer *o, size_t sample) {
  flockfile(stderr);
  int written = fprintf(
      stderr,
      "{\"actor\":\"threadinfo-observer\",\"monotonic_ns\":%" PRIu64
      ",\"pid\":%d,\"seq\":%zu,\"phase\":\"%s\","
      "\"api\":\"proc_pidinfo\",\"edge\":\"before\",\"result\":null,"
      "\"sourcehash\":\"%s\",\"owner_tid\":%" PRIu64 ",\"flavor\":%d}\n",
      observer_now(o), getpid(), sample * 2 + 1, o->phase, PROBE_SOURCE_SHA,
      o->owner_tid, PROC_PIDTHREADID64INFO);
  int flushed = fflush(stderr);
  funlockfile(stderr);
  if (written < 0 || flushed != 0)
    return 74;

  // Flavor 15 selects the kernel thread ID; flavor 5 selects cthread_self.
  // XNU proc_info.c and bsd_kern.c at ac9718fb1af618d5ce8678d0dc6e8a58f252216f.
  // This call takes kernel locks and can block even without suspending threads.
  struct proc_threadinfo info = {0};
  errno = 0;
  int bytes = proc_pidinfo(getpid(), PROC_PIDTHREADID64INFO, o->owner_tid,
                           &info, sizeof(info));
  int error = bytes <= 0 ? errno : 0;
  bool valid = bytes == sizeof(info);
  char values[160];
  if (valid)
    snprintf(values, sizeof(values),
             "\"run_state\":%d,\"user_time_ns\":%" PRIu64
             ",\"system_time_ns\":%" PRIu64,
             info.pth_run_state, info.pth_user_time, info.pth_system_time);
  else
    strcpy(values, "\"run_state\":null,\"user_time_ns\":null,"
                   "\"system_time_ns\":null");
  flockfile(stderr);
  written = fprintf(
      stderr,
      "{\"actor\":\"threadinfo-observer\",\"monotonic_ns\":%" PRIu64
      ",\"pid\":%d,\"seq\":%zu,\"phase\":\"%s\","
      "\"api\":\"proc_pidinfo\",\"edge\":\"return\",\"result\":%d,"
      "\"sourcehash\":\"%s\",\"owner_tid\":%" PRIu64
      ",\"flavor\":%d,\"expected_bytes\":%zu,\"error\":%d,\"valid\":%s,%s}\n",
      observer_now(o), getpid(), sample * 2 + 2, o->phase, bytes,
      PROBE_SOURCE_SHA, o->owner_tid, PROC_PIDTHREADID64INFO, sizeof(info),
      error, valid ? "true" : "false", values);
  flushed = fflush(stderr);
  funlockfile(stderr);
  if (written < 0 || flushed != 0)
    return 74;
  return valid ? 0 : 71;
}

static int interrupt_vcpu(const struct observer *o) {
  flockfile(stderr);
  int written = fprintf(
      stderr,
      "{\"actor\":\"interrupt-observer\",\"monotonic_ns\":%" PRIu64
      ",\"pid\":%d,\"seq\":1,\"phase\":\"%s\","
      "\"api\":\"hv_vcpu_interrupt\",\"edge\":\"before\",\"result\":null,"
      "\"sourcehash\":\"%s\",\"vcpu\":%u,\"owner_tid\":%" PRIu64 "}\n",
      observer_now(o), getpid(), o->phase, PROBE_SOURCE_SHA, o->vcpu,
      o->owner_tid);
  int flushed = fflush(stderr);
  funlockfile(stderr);
  if (written < 0 || flushed != 0)
    return 74;

  // Unlike register access, this public API has no owning-thread restriction.
  // QEMU a3565937b39779d4e3704298095f566e7559ad53 uses it in
  // hvf_kick_vcpu_thread.
  hv_vcpuid_t target = o->vcpu;
  hv_return_t result = hv_vcpu_interrupt(&target, 1);
  flockfile(stderr);
  written =
      fprintf(stderr,
              "{\"actor\":\"interrupt-observer\",\"monotonic_ns\":%" PRIu64
              ",\"pid\":%d,\"seq\":2,\"phase\":\"%s\","
              "\"api\":\"hv_vcpu_interrupt\",\"edge\":\"return\",\"result\":%d,"
              "\"sourcehash\":\"%s\",\"vcpu\":%u,\"owner_tid\":%" PRIu64 "}\n",
              observer_now(o), getpid(), o->phase, (int)result,
              PROBE_SOURCE_SHA, o->vcpu, o->owner_tid);
  flushed = fflush(stderr);
  funlockfile(stderr);
  if (written < 0 || flushed != 0)
    return 74;
  return result == HV_SUCCESS ? 0 : 70;
}

static int drain_kernel_markers(const struct observer *o, size_t *next) {
  while (*next < KERNEL_MARKER_CAPACITY) {
    const struct kernel_marker_slot *slot = &o->markers[*next];
    uint64_t commit = atomic_load_explicit(&slot->commit, memory_order_acquire);
    if (commit == 0)
      break;
    if (commit != *next + 1)
      return 77;
    // Intel-only publish contract: copyout writes an aligned 8-byte commit
    // after the body, and the producer never reuses a committed slot.
    const struct kernel_marker_body body = slot->body;
    uint32_t event = (uint32_t)body.meta;
    flockfile(stderr);
    int written = fprintf(
        stderr,
        "{\"actor\":\"kernel-marker-observer\",\"monotonic_ns\":%" PRIu64
        ",\"pid\":%d,\"seq\":%zu,\"phase\":\"%s\","
        "\"api\":\"kernel_marker\",\"edge\":\"fact\",\"result\":0,"
        "\"sourcehash\":\"%s\",\"slot\":%zu,\"commit\":%" PRIu64
        ",\"kernel_timestamp_ns\":%" PRIu64 ",\"caller_pc\":%" PRIu64
        ",\"arg0\":%" PRIu64 ",\"arg1\":%" PRIu64 ",\"tid\":%" PRIu64
        ",\"meta\":%" PRIu64 ",\"kind\":%" PRIu32
        ",\"return\":%s,\"cpu\":%" PRIu32 "}\n",
        observer_now(o), getpid(), *next + 1, o->phase, PROBE_SOURCE_SHA, *next,
        commit, body.timestamp_ns, body.caller_pc, body.arg0, body.arg1,
        body.tid, body.meta, event >> 1, (event & 1) ? "true" : "false",
        (uint32_t)(body.meta >> 32));
    int flushed = fflush(stderr);
    funlockfile(stderr);
    if (written < 0 || flushed != 0)
      return 74;
    ++*next;
  }
  return 0;
}

static void *observe_sentinel(void *argument) {
  const struct observer *o = argument;
  uint64_t started = observer_now(o), first_tag_ns = 0;
  const uint64_t samples[] = {100000000, 500000000};
  bool seen = false;
  size_t next_marker = 0;
  for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
    int error = 0;
    uint64_t now;
    uint8_t actual;
    do {
      if (o->kind == OBSERVER_KERNELMARKERS) {
        int result = drain_kernel_markers(o, &next_marker);
        if (result != 0)
          return (void *)(uintptr_t)result;
      }
      now = observer_now(o);
      actual = *(const volatile uint8_t *)(o->memory + SENTINEL);
      if (actual == TAG && !seen) {
        seen = true;
        first_tag_ns = now - started;
      }
      if (now - started >= samples[i])
        break;
      struct timespec delay = {
          .tv_nsec = o->kind == OBSERVER_KERNELMARKERS ? 1000000 : 5000000};
      if (nanosleep(&delay, NULL) != 0 && errno != EINTR)
        error = errno;
    } while (error == 0);
    // This helper owns only its immutable observer state and stderr records.
    // It never accesses the main probe's sequence or stdout state.
    flockfile(stderr);
    int written =
        fprintf(stderr,
                "{\"actor\":\"hlt-observer\",\"monotonic_ns\":%" PRIu64
                ",\"pid\":%d,\"seq\":%zu,\"phase\":\"%s\","
                "\"api\":\"sentinel_sample\",\"edge\":\"fact\",\"result\":%d,"
                "\"sourcehash\":\"%s\",\"vcpu\":%u,\"scheduled_ns\":%" PRIu64
                ",\"elapsed_ns\":%" PRIu64 ",\"sentinel\":%u,\"tag_seen\":%s,"
                "\"first_tag_ns\":%" PRIu64 "}\n",
                now, getpid(), i + 1, o->phase, error, PROBE_SOURCE_SHA,
                o->vcpu, samples[i], now - started, actual,
                seen ? "true" : "false", first_tag_ns);
    int flushed = fflush(stderr);
    funlockfile(stderr);
    if (written < 0 || flushed != 0)
      return (void *)(uintptr_t)74;
    if (error != 0)
      return (void *)(uintptr_t)71;
    if (o->kind == OBSERVER_THREADINFO) {
      int result = observe_thread_info(o, i);
      if (result != 0)
        return (void *)(uintptr_t)result;
    }
    if (o->kind == OBSERVER_INTERRUPT && i == 0) {
      int result = interrupt_vcpu(o);
      if (result != 0)
        return (void *)(uintptr_t)result;
    }
  }
  if (o->kind == OBSERVER_KERNELMARKERS) {
    while (!atomic_load_explicit(o->stop, memory_order_acquire) &&
           observer_now(o) - started < 2000000000) {
      int result = drain_kernel_markers(o, &next_marker);
      if (result != 0)
        return (void *)(uintptr_t)result;
      struct timespec delay = {.tv_nsec = 1000000};
      if (nanosleep(&delay, NULL) != 0 && errno != EINTR)
        return (void *)(uintptr_t)71;
    }
    int result = drain_kernel_markers(o, &next_marker);
    flockfile(stderr);
    int written = fprintf(
        stderr,
        "{\"actor\":\"kernel-marker-observer\",\"api\":\"kernel_marker_window_"
        "end\","
        "\"edge\":\"fact\",\"result\":%d,\"pid\":%d,\"slots\":%zu,"
        "\"elapsed_ns\":%" PRIu64
        ",\"limit_ns\":2000000000,\"stop_requested\":%s}\n",
        result, getpid(), next_marker, observer_now(o) - started,
        atomic_load_explicit(o->stop, memory_order_acquire) ? "true" : "false");
    int flushed = fflush(stderr);
    funlockfile(stderr);
    return (void *)(uintptr_t)(written < 0 || flushed != 0 ? 74 : result);
  }
  return NULL;
}

static bool fact(struct probe *p, const char *api, const char *edge,
                 int64_t result, uint64_t arg0, uint64_t arg1, uint64_t arg2) {
  uint64_t ns = (uint64_t)((__uint128_t)mach_absolute_time() *
                           p->timebase.numer / p->timebase.denom);
  char result_text[32];
  if (strcmp(edge, "before") == 0)
    strcpy(result_text, "null");
  else
    snprintf(result_text, sizeof(result_text), "%" PRId64, result);
  int written =
      printf("{\"monotonic_ns\":%" PRIu64 ",\"pid\":%d,\"seq\":%" PRIu64
             ",\"phase\":\"%s\",\"api\":\"%s\",\"edge\":\"%s\","
             "\"result\":%s,\"sourcehash\":\"%s\",\"arg0\":%" PRIu64
             ",\"arg1\":%" PRIu64 ",\"arg2\":%" PRIu64 "}\n",
             ns, getpid(), ++p->sequence, p->phase, api, edge, result_text,
             PROBE_SOURCE_SHA, arg0, arg1, arg2);
  if (written < 0 || fflush(stdout) != 0)
    p->output_failed = true;
  return !p->output_failed;
}

static bool before(struct probe *p, const char *api, uint64_t a, uint64_t b,
                   uint64_t c) {
  // This record precedes the user-space call. It does not prove kernel entry.
  bool logged = fact(p, api, "before", 0, a, b, c);
  return logged || p->cleaning;
}

static hv_return_t returned(struct probe *p, const char *api,
                            hv_return_t result, uint64_t a, uint64_t b,
                            uint64_t c) {
  fact(p, api, "return", result, a, b, c);
  return result;
}

#define CALL(p, api, expression, a, b, c)                                      \
  (before(p, api, a, b, c) ? returned(p, api, (expression), a, b, c) : HV_ERROR)
#define TRY(expression)                                                        \
  do {                                                                         \
    int try_status_ = (expression);                                            \
    if (try_status_ != 0)                                                      \
      return try_status_;                                                      \
  } while (0)

static int status(struct probe *p, hv_return_t result) {
  if (p->output_failed)
    return 74;
  if (result == HV_UNSUPPORTED || result == HV_NO_DEVICE || result == HV_DENIED)
    return 77;
  return result == HV_SUCCESS ? 0 : 70;
}

static int capabilities(struct probe *p) {
  int translated = 0;
  size_t size = sizeof(translated);
  before(p, "sysctl.proc_translated", 0, 0, 0);
  int rc = sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0);
  int error = rc == 0 ? 0 : errno;
  fact(p, "sysctl.proc_translated", "return", error, (uint64_t)translated, 0,
       0);
  if (translated || (rc != 0 && error != ENOENT))
    return 77;
  int supported = 0;
  size = sizeof(supported);
  before(p, "kern.hv_support", 0, 0, 0);
  rc = sysctlbyname("kern.hv_support", &supported, &size, NULL, 0);
  fact(p, "kern.hv_support", "return", rc == 0 ? 0 : errno, (uint64_t)supported,
       0, 0);
  if (rc != 0 || supported != 1 || sysconf(_SC_PAGESIZE) != PAGE_BYTES)
    return 77;
  const struct {
    hv_vmx_capability_t field;
    uint64_t *value;
  } caps[] = {
      {HV_VMX_CAP_CR0_FIXED0, &p->cr0_fixed0},
      {HV_VMX_CAP_CR0_FIXED1, &p->cr0_fixed1},
      {HV_VMX_CAP_CR4_FIXED0, &p->cr4_fixed0},
      {HV_VMX_CAP_CR4_FIXED1, &p->cr4_fixed1},
  };
  for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); ++i) {
    TRY(status(p, CALL(p, "hv_vmx_read_capability",
                       hv_vmx_read_capability(caps[i].field, caps[i].value),
                       caps[i].field, 0, 0)));
    fact(p, "capability_value", "fact", 0, caps[i].field, *caps[i].value, 0);
  }
  return p->output_failed ? 74 : 0;
}

static int write_field(struct probe *p, uint32_t field, uint64_t value) {
  TRY(status(p, CALL(p, "hv_vmx_vcpu_write_vmcs",
                     hv_vmx_vcpu_write_vmcs(p->vcpu, field, value), field,
                     value, 0)));
  uint64_t actual = 0;
  TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                     hv_vmx_vcpu_read_vmcs(p->vcpu, field, &actual), field, 0,
                     0)));
  fact(p, "vmcs_readback", "fact", actual == value ? 0 : 70, field, value,
       actual);
  return actual == value ? 0 : 70;
}

static int control(struct probe *p, uint32_t field, uint64_t desired,
                   uint64_t forbidden, uint64_t *applied) {
  uint64_t must_one = 0, may_one = 0;
  // Apple's hv_vmx.h defines allowed_0 as the mask of bits that must be one.
  TRY(status(p, CALL(p, "hv_vmx_vcpu_get_cap_write_vmcs",
                     hv_vmx_vcpu_get_cap_write_vmcs(p->vcpu, field, &must_one,
                                                    &may_one),
                     field, 0, 0)));
  fact(p, "vmcs_masks", "fact", 0, field, must_one, may_one);
  if ((must_one & ~may_one) || (desired & ~may_one) || (must_one & forbidden)) {
    fact(p, "control_not_established", "fact", 77, field, desired, forbidden);
    return 77;
  }
  *applied = must_one | desired;
  return write_field(p, field, *applied);
}

static int configure(struct probe *p, const struct phase_case *spec) {
  uint64_t applied, entry;
  // Intel SDM vol. 3C, 24.6: activate secondary controls (31), HLT exiting (7),
  // EPT (secondary 1), unrestricted guest (secondary 7). See
  // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  // Finite run_until enables the timer before applying pending controls.
  bool mtf_forever = spec->mtf_phase && spec->forever;
  TRY(control(p, VMCS_CTRL_PIN_BASED,
              p->timer_only && !mtf_forever ? (1ULL << 6) : 0,
              mtf_forever ? (1ULL << 6) : 0, &applied));
  if (p->mtf_phase) {
    uint64_t must_one = 0, may_one = 0;
    TRY(status(p, CALL(p, "hv_vmx_vcpu_get_cap_write_vmcs",
                       hv_vmx_vcpu_get_cap_write_vmcs(
                           p->vcpu, VMCS_CTRL_CPU_BASED, &must_one, &may_one),
                       VMCS_CTRL_CPU_BASED, 0, 0)));
    bool toggle = !(must_one & (1ULL << 27)) && (may_one & (1ULL << 27));
    fact(p, "mtf_toggle_capability", "fact", toggle ? 0 : 77, must_one, may_one,
         1ULL << 27);
    if (!toggle)
      return 77;
  }
  uint64_t primary = (1ULL << 31) | (p->timer_only ? 0 : (1ULL << 7));
  // AppleHV 25G76 prepare_cond_vmcs applies primary controls only with
  // both CR8 exits or TPR shadow. This phase tests that coupled condition.
  if (p->cr8_exits)
    primary |= (1ULL << 19) | (1ULL << 20);
  if (p->mtf_phase)
    primary |= 1ULL << 27;
  TRY(control(p, VMCS_CTRL_CPU_BASED, primary,
              (1ULL << 2) | (1ULL << 22) | (p->mtf_phase ? 0 : (1ULL << 27)) |
                  (p->timer_only ? (1ULL << 7) : 0),
              &applied));
  TRY(control(p, VMCS_CTRL_CPU_BASED2, (1ULL << 1) | (1ULL << 7), 1ULL << 14,
              &applied));
  TRY(control(p, VMCS_CTRL_VMENTRY_CONTROLS, 0,
              (1ULL << 9) | (1ULL << 10) | (1ULL << 11), &entry));
  // SDM 26.3.1: unrestricted guest relaxes CR0.PE/PG fixed-one requirements.
  uint64_t cr0 = ((p->cr0_fixed0 | (1ULL << 4)) & ~((1ULL << 31) | 1ULL)) |
                 p->profile->cr0_set | p->paging->cr0_set;
  uint64_t cr4 = p->cr4_fixed0;
  if ((cr0 & ~p->cr0_fixed1) || (cr4 & ~p->cr4_fixed1) ||
      (cr0 & ((1ULL << 29) | (1ULL << 30))) || (cr4 & (1ULL << 17)) ||
      (p->paging->cr3 != 0 && (cr4 & (1ULL << 5)))) {
    fact(p, "cr_not_established", "fact", 77, cr0, cr4, 0);
    return 77;
  }
  TRY(write_field(p, VMCS_GUEST_CR0, cr0));
  TRY(write_field(p, VMCS_GUEST_CR3, p->paging->cr3));
  TRY(write_field(p, VMCS_GUEST_CR4, cr4));
  const struct {
    uint32_t selector, base, limit, access;
    const struct guest_segment *state;
  } segments[] = {
      {VMCS_GUEST_CS, VMCS_GUEST_CS_BASE, VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_AR,
       &p->profile->cs},
      {VMCS_GUEST_DS, VMCS_GUEST_DS_BASE, VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR,
       &p->profile->data},
      {VMCS_GUEST_ES, VMCS_GUEST_ES_BASE, VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR,
       &p->profile->data},
      {VMCS_GUEST_SS, VMCS_GUEST_SS_BASE, VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR,
       &p->profile->data},
      {VMCS_GUEST_FS, VMCS_GUEST_FS_BASE, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR,
       &p->profile->data},
      {VMCS_GUEST_GS, VMCS_GUEST_GS_BASE, VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR,
       &p->profile->data},
      {VMCS_GUEST_TR, VMCS_GUEST_TR_BASE, VMCS_GUEST_TR_LIMIT, VMCS_GUEST_TR_AR,
       &p->profile->tr},
      {VMCS_GUEST_LDTR, VMCS_GUEST_LDTR_BASE, VMCS_GUEST_LDTR_LIMIT,
       VMCS_GUEST_LDTR_AR, &p->profile->ldtr},
  };
  // SDM vol. 3C, 27.3.1.2 describes VM-entry segment-state checks.
  for (size_t i = 0; i < sizeof(segments) / sizeof(segments[0]); ++i) {
    const struct guest_segment *state = segments[i].state;
    TRY(write_field(p, segments[i].selector, state->selector));
    TRY(write_field(p, segments[i].base, state->base));
    TRY(write_field(p, segments[i].limit, state->limit));
    TRY(write_field(p, segments[i].access, state->rights));
  }
  const struct {
    uint32_t field;
    uint64_t value;
  } fields[] = {
      {VMCS_GUEST_GDTR_BASE, p->profile->gdtr_base},
      {VMCS_GUEST_GDTR_LIMIT, p->profile->gdtr_limit},
      {VMCS_GUEST_IDTR_BASE, 0},
      {VMCS_GUEST_IDTR_LIMIT, 0x3ff},
      {VMCS_GUEST_RIP, CODE},
      {VMCS_GUEST_RSP, 0xff0},
      {VMCS_GUEST_RFLAGS, 2},
      {VMCS_GUEST_DR7, 0x400},
      {VMCS_GUEST_IA32_EFER, 0},
      {VMCS_GUEST_INTERRUPTIBILITY, 0},
      {VMCS_GUEST_ACTIVITY_STATE, 0},
      {VMCS_GUEST_DEBUG_EXC, 0},
      {VMCS_GUEST_IA32_SYSENTER_CS, 0},
      {VMCS_GUEST_SYSENTER_ESP, 0},
      {VMCS_GUEST_SYSENTER_EIP, 0},
      {VMCS_CTRL_VMENTRY_IRQ_INFO, 0},
      {VMCS_CTRL_VMENTRY_EXC_ERROR, 0},
      {VMCS_CTRL_VMENTRY_INSTR_LEN, 0},
      {VMCS_CTRL_EXC_BITMAP, UINT32_MAX},
      {VMCS_CTRL_PF_ERROR_MASK, 0},
  };
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
    TRY(write_field(p, fields[i].field, fields[i].value));
  // Only public VMCS fields are written. Framework-owned state stays untouched.
  // SDM 26.3: when VM entry loads debug controls (bit 2), clear IA32_DEBUGCTL.
  if (entry & (1ULL << 2)) {
    TRY(status(p, CALL(p, "hv_vcpu_write_msr",
                       hv_vcpu_write_msr(p->vcpu, 0x1d9, 0), 0x1d9, 0, 0)));
    uint64_t debugctl = UINT64_MAX;
    TRY(status(p,
               CALL(p, "hv_vcpu_read_msr",
                    hv_vcpu_read_msr(p->vcpu, 0x1d9, &debugctl), 0x1d9, 0, 0)));
    fact(p, "debugctl_readback", "fact", debugctl == 0 ? 0 : 70, debugctl, 0,
         0);
    if (debugctl != 0)
      return 70;
  }
  fact(p, "guest_validity_not_established", "fact", 77, 0, 0, 0);
  return p->output_failed ? 74 : 0;
}

static int prepare_kernel_markers(struct probe *p) {
  if (!before(p, "kernel_marker_mmap", PAGE_BYTES, PROT_READ | PROT_WRITE, 0))
    return 74;
  void *memory = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
  int error = memory == MAP_FAILED ? errno : 0;
  fact(p, "kernel_marker_mmap", "return", error, PAGE_BYTES,
       PROT_READ | PROT_WRITE, 0);
  if (memory == MAP_FAILED)
    return 71;
  p->markers = memory;
  memset(memory, 0, PAGE_BYTES);
  for (size_t i = 0; i < KERNEL_MARKER_CAPACITY; ++i)
    atomic_init(&p->markers[i].commit, 0);
  if (!before(p, "kernel_marker_mlock", PAGE_BYTES, 0, 0))
    return 74;
  int rc = mlock(memory, PAGE_BYTES);
  p->marker_locked = rc == 0;
  fact(p, "kernel_marker_mlock", "return", rc == 0 ? 0 : errno, PAGE_BYTES, 0,
       0);
  if (p->output_failed)
    return 74;
  if (rc != 0)
    return 77;
  return fact(p, "kernel_marker_buffer", "fact", 0, (uintptr_t)memory,
              KERNEL_MARKER_CAPACITY, sizeof(struct kernel_marker_slot))
             ? 0
             : 74;
}

static int gate(struct probe *p, const char *name) {
  // fflush proves only local output completion. The controller must receive
  // this named gate and independently check the runner before sending G.
  if (!fact(p, name, "fact", 0, 'G', 0, 0))
    return 74;
  for (;;) {
    unsigned char command = 0;
    ssize_t bytes;
    do {
      bytes = read(STDIN_FILENO, &command, 1);
    } while (bytes < 0 && errno == EINTR);
    if (bytes < 0) {
      fact(p, name, "protocol_error", 71, errno, 0, 'G');
      return 71;
    }
    if (bytes == 0) {
      fact(p, name, "protocol_error", 75, 0, 0, 'G');
      return 75;
    }
    if (command == 'P' && p->markers != NULL &&
        strcmp(name, "run_ready") == 0) {
      errno = 0;
      ssize_t probed = write(STDOUT_FILENO, "", 0);
      int error = probed < 0 ? errno : 0;
      uint64_t commit =
          atomic_load_explicit(&p->markers[0].commit, memory_order_acquire);
      bool acknowledged = probed == 0 && commit == 1;
      if (!fact(p, acknowledged ? "kernel_marker_ack" : "kernel_marker_unarmed",
                "fact", 0, commit, 1, error))
        return 74;
      continue;
    }
    if (command != 'G') {
      fact(p, name, "protocol_error", 64, command, 'G', 0);
      return 64;
    }
    return fact(p, name, "released", 0, command, 0, 0) ? 0 : 74;
  }
}

static int prepare_run(struct probe *p, bool armed) {
  // Intel SDM vol. 2: C6 /0 writes the sentinel before each case's tail.
  // Guest validity remains unestablished until the observations below agree.
  uint8_t initial = *(volatile uint8_t *)(p->memory + SENTINEL);
  fact(p, "sentinel_initial", "fact", initial == 0 ? 0 : 77, initial, TAG, 0);
  if (initial != 0)
    return 77;
  int result = armed ? gate(p, "run_ready") : 0;
  if (result != 0)
    fact(p, "guest_not_executed_protocol_error", "fact", result, 0, 0, 0);
  return result;
}

static int run_once(struct probe *p, const struct phase_case *spec) {
  uint64_t idle_before = 0;
  if (spec->observer == OBSERVER_INTERRUPT) {
    TRY(status(p, CALL(p, "hv_vcpu_get_idle_time",
                       hv_vcpu_get_idle_time(p->vcpu, &idle_before), p->vcpu, 0,
                       0)));
    fact(p, "idle_time_before", "fact", 0, idle_before, 0, 0);
  }
  uint64_t ticks =
      (uint64_t)((__uint128_t)20000000 * p->timebase.denom / p->timebase.numer);
  // Apple hv_vcpu_run_until: absolute mach time, finite VMX preemption timer.
  // https://developer.apple.com/documentation/hypervisor/hv_vcpu_run_until(_:_:)
  uint64_t duration = spec->forever ? 0 : 20000000;
  const char *boundary =
      spec->control ? "control_deadline" : "hv_vcpu_run_until";
  if (!before(p, boundary, p->vcpu, 0, duration))
    return 74;
  uint64_t deadline = spec->forever
                          ? HV_DEADLINE_FOREVER
                          : mach_absolute_time() + (ticks ? ticks : 1);
  if (spec->control) {
    fact(p, "guest_not_executed_control", "fact", 0, p->vcpu, deadline,
         20000000);
    return p->output_failed ? 74 : 0;
  }
  hv_return_t result = hv_vcpu_run_until(p->vcpu, deadline);
  returned(p, "hv_vcpu_run_until", result, p->vcpu, deadline, duration);
  if (spec->armed)
    TRY(gate(p, "run_return_ready"));
  hv_return_t idle_result = HV_SUCCESS;
  if (spec->observer == OBSERVER_INTERRUPT) {
    uint64_t idle_after = 0;
    idle_result =
        CALL(p, "hv_vcpu_get_idle_time",
             hv_vcpu_get_idle_time(p->vcpu, &idle_after), p->vcpu, 0, 0);
    if (idle_result == HV_SUCCESS)
      fact(p, "idle_time_delta", "fact", idle_after >= idle_before ? 0 : 77,
           idle_before, idle_after,
           idle_after >= idle_before ? idle_after - idle_before : 0);
  }
  TRY(status(p, result));
  TRY(status(p, idle_result));
  uint64_t reason = 0, rip = 0, length = 0;
  TRY(status(p,
             CALL(p, "hv_vmx_vcpu_read_vmcs",
                  hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_RO_EXIT_REASON, &reason),
                  VMCS_RO_EXIT_REASON, 0, 0)));
  TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                     hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_GUEST_RIP, &rip),
                     VMCS_GUEST_RIP, 0, 0)));
  if (p->guest->instruction_length != 0 &&
      (spec->observer != OBSERVER_INTERRUPT ||
       (!(reason & (1ULL << 31)) &&
        (reason & 0xffff) == p->guest->exit_reason)))
    TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                       hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_RO_VMEXIT_INSTR_LEN,
                                             &length),
                       VMCS_RO_VMEXIT_INSTR_LEN, 0, 0)));
  uint8_t actual = *(volatile uint8_t *)(p->memory + SENTINEL);
  fact(p, "guest_observation", "fact", 0, actual, rip, length);
  uint64_t activity = 0;
  if (spec->observer == OBSERVER_INTERRUPT || spec->timer_only) {
    TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                       hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_GUEST_ACTIVITY_STATE,
                                             &activity),
                       VMCS_GUEST_ACTIVITY_STATE, 0, 0)));
    fact(p, spec->timer_only ? "timer_guest_state" : "interrupt_guest_state",
         "fact", 0, reason, rip, activity);
  }
  // SDM appendix C: bit 31 marks VM-entry failure.
  bool length_matches = p->guest->instruction_length == 0 ||
                        length == p->guest->instruction_length;
  p->guest_verified =
      !(reason & (1ULL << 31)) && (reason & 0xffff) == p->guest->exit_reason &&
      actual == TAG &&
      rip == CODE + p->profile->mov_length + p->guest->tail_offset &&
      length_matches &&
      (!spec->timer_only || activity == p->guest->activity_state);
  fact(p, p->guest_verified ? p->guest->verified_fact : "guest_not_established",
       "fact", p->guest_verified ? 0 : 77, reason, rip, length);
  return p->guest_verified ? 0 : 77;
}

enum { MTF_FIELDS = 10, MTF_REGS = 16 };
struct mtf_state {
  uint64_t fields[MTF_FIELDS], regs[MTF_REGS];
};
static const uint32_t mtf_fields[MTF_FIELDS] = {VMCS_GUEST_RIP,
                                                VMCS_GUEST_RSP,
                                                VMCS_GUEST_RFLAGS,
                                                VMCS_GUEST_ACTIVITY_STATE,
                                                VMCS_GUEST_INTERRUPTIBILITY,
                                                VMCS_CTRL_VMENTRY_IRQ_INFO,
                                                VMCS_CTRL_PIN_BASED,
                                                VMCS_CTRL_CPU_BASED,
                                                VMCS_GUEST_VMX_TIMER_VALUE,
                                                VMCS_CTRL_VMEXIT_CONTROLS};
static const hv_x86_reg_t mtf_regs[MTF_REGS] = {
    HV_X86_RAX, HV_X86_RBX, HV_X86_RCX, HV_X86_RDX, HV_X86_RSI, HV_X86_RDI,
    HV_X86_RBP, HV_X86_RSP, HV_X86_R8,  HV_X86_R9,  HV_X86_R10, HV_X86_R11,
    HV_X86_R12, HV_X86_R13, HV_X86_R14, HV_X86_R15};

static int mtf_snapshot(struct probe *p, unsigned stage,
                        struct mtf_state *state) {
  for (size_t i = 0; i < MTF_FIELDS; ++i) {
    TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                       hv_vmx_vcpu_read_vmcs(p->vcpu, mtf_fields[i],
                                             &state->fields[i]),
                       mtf_fields[i], stage, 0)));
    fact(p, "mtf_guest_vmcs", "fact", 0, stage, mtf_fields[i],
         state->fields[i]);
  }
  for (size_t i = 0; i < MTF_REGS; ++i) {
    TRY(status(
        p, CALL(p, "hv_vcpu_read_register",
                hv_vcpu_read_register(p->vcpu, mtf_regs[i], &state->regs[i]),
                mtf_regs[i], stage, 0)));
    fact(p, "mtf_guest_register", "fact", 0, stage, mtf_regs[i],
         state->regs[i]);
  }
  // A timer value is not a live countdown when the exit-save bit is clear.
  fact(p, "mtf_timer_save_enabled", "fact", 0, stage,
       (state->fields[9] >> 22) & 1, state->fields[8]);
  fact(p, "mtf_snapshot_complete", "fact", 0, stage, state->fields[0],
       state->fields[3]);
  return p->output_failed ? 74 : 0;
}

static int mtf_step(struct probe *p, const struct phase_case *spec,
                    unsigned stage, uint64_t expected_rip,
                    uint64_t expected_activity) {
  uint64_t ticks =
      (uint64_t)((__uint128_t)20000000 * p->timebase.denom / p->timebase.numer);
  uint64_t duration = spec->forever ? 0 : 20000000;
  if (!before(p, "mtf_run_until", p->vcpu, stage, duration))
    return 74;
  uint64_t deadline = spec->forever
                          ? HV_DEADLINE_FOREVER
                          : mach_absolute_time() + (ticks ? ticks : 1);
  hv_return_t rc = hv_vcpu_run_until(p->vcpu, deadline);
  returned(p, "mtf_run_until", rc, p->vcpu, stage, deadline);
  TRY(status(p, rc));
  uint64_t reason = 0, rip = 0, activity = 0;
  TRY(status(p,
             CALL(p, "hv_vmx_vcpu_read_vmcs",
                  hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_RO_EXIT_REASON, &reason),
                  VMCS_RO_EXIT_REASON, stage, 0)));
  TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                     hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_GUEST_RIP, &rip),
                     VMCS_GUEST_RIP, stage, 0)));
  TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                     hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_GUEST_ACTIVITY_STATE,
                                           &activity),
                     VMCS_GUEST_ACTIVITY_STATE, stage, 0)));
  uint64_t tag = *(volatile uint8_t *)(p->memory + SENTINEL);
  bool valid = !(reason & (1ULL << 31)) && (reason & 0xffff) == 37 &&
               rip == expected_rip && activity == expected_activity &&
               tag == TAG;
  fact(p, "mtf_exit", "fact", valid ? 0 : 77, reason, rip, activity);
  fact(p, "mtf_exit_tag", "fact", valid ? 0 : 77, stage, tag, 0);
  if (!valid) {
    fact(p, "mtf_unexpected_exit", "fact", 77, reason, stage, 0);
    return 77;
  }
  return p->output_failed ? 74 : 0;
}

static int run_mtf(struct probe *p, const struct phase_case *spec) {
  struct mtf_state before_state = {0}, after_state = {0};
  TRY(mtf_step(p, spec, 1, CODE + p->profile->mov_length, 0));
  if (spec->mtf_phase == 1) {
    p->guest_verified = true;
    fact(p, "mtf_mov_verified", "fact", 0, 37, CODE + p->profile->mov_length,
         TAG);
    return p->output_failed ? 74 : 0;
  }
  TRY(gate(p, "mtf_mov_checkpoint_ready"));
  TRY(mtf_step(p, spec, 2, CODE + p->profile->mov_length + 1,
               spec->mtf_phase == 4 ? 0 : 1));
  if (spec->mtf_phase == 4) {
    p->guest_verified = true;
    fact(p, "mtf_nop_verified", "fact", 0, 37,
         CODE + p->profile->mov_length + 1, 0);
    return p->output_failed ? 74 : 0;
  }
  TRY(mtf_snapshot(p, 2, &before_state));
  uint64_t primary = before_state.fields[7];
  if (before_state.fields[0] != CODE + p->profile->mov_length + 1 ||
      before_state.fields[3] != 1 || !(primary & (1ULL << 27)) ||
      (primary & (1ULL << 7)) ||
      (primary & ((1ULL << 19) | (1ULL << 20))) !=
          ((1ULL << 19) | (1ULL << 20)))
    return 77;
  p->guest_verified = true;
  fact(p, "mtf_hlt_verified", "fact", 0, 37, before_state.fields[0],
       before_state.fields[3]);
  TRY(gate(p, "mtf_checkpoint_ready"));
  if (spec->mtf_phase == 2)
    return p->output_failed ? 74 : 0;
  uint64_t must_one = 0, may_one = 0;
  TRY(status(p, CALL(p, "hv_vmx_vcpu_get_cap_write_vmcs",
                     hv_vmx_vcpu_get_cap_write_vmcs(
                         p->vcpu, VMCS_CTRL_CPU_BASED, &must_one, &may_one),
                     VMCS_CTRL_CPU_BASED, 0, 0)));
  if (must_one & (1ULL << 27))
    return 77;
  TRY(write_field(p, VMCS_CTRL_CPU_BASED, primary & ~(1ULL << 27)));
  TRY(mtf_snapshot(p, 3, &after_state));
  bool same = after_state.fields[7] == (primary & ~(1ULL << 27));
  for (size_t i = 0; i < MTF_FIELDS; ++i)
    if (i != 7 && i != 8 && before_state.fields[i] != after_state.fields[i])
      same = false;
  for (size_t i = 0; i < MTF_REGS; ++i)
    if (before_state.regs[i] != after_state.regs[i])
      same = false;
  if (after_state.fields[5] & (1ULL << 31))
    same = false;
  fact(p, "mtf_resume_compared_scope", "fact", 0, VMCS_GUEST_VMX_TIMER_VALUE,
       VMCS_CTRL_CPU_BASED, 1ULL << 27);
  fact(p, "mtf_resume_state_equal", "fact", same ? 0 : 77,
       before_state.fields[0], after_state.fields[0], after_state.fields[3]);
  if (!same)
    return 77;
  uint64_t ticks =
      (uint64_t)((__uint128_t)20000000 * p->timebase.denom / p->timebase.numer);
  if (!before(p, "mtf_resume_run_until", p->vcpu, 0, 20000000))
    return 74;
  uint64_t deadline = mach_absolute_time() + (ticks ? ticks : 1);
  hv_return_t rc = hv_vcpu_run_until(p->vcpu, deadline);
  returned(p, "mtf_resume_run_until", rc, p->vcpu, deadline, 20000000);
  TRY(status(p, rc));
  uint64_t reason = 0, rip = 0, activity = 0;
  TRY(status(p,
             CALL(p, "hv_vmx_vcpu_read_vmcs",
                  hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_RO_EXIT_REASON, &reason),
                  VMCS_RO_EXIT_REASON, 0, 0)));
  TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                     hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_GUEST_RIP, &rip),
                     VMCS_GUEST_RIP, 0, 0)));
  TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                     hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_GUEST_ACTIVITY_STATE,
                                           &activity),
                     VMCS_GUEST_ACTIVITY_STATE, 0, 0)));
  bool timer_exit = !(reason & (1ULL << 31)) && (reason & 0xffff) == 52 &&
                    rip == CODE + p->profile->mov_length + 1 && activity == 1;
  fact(p, "mtf_resume_exit", "fact", timer_exit ? 0 : 77, reason, rip,
       activity);
  if (p->output_failed)
    return 74;
  return timer_exit ? 0 : 77;
}

static int watched_run(struct probe *p, const struct phase_case *spec) {
  uint64_t owner_tid = 0;
  if (spec->observer == OBSERVER_THREADINFO ||
      spec->observer == OBSERVER_INTERRUPT ||
      spec->observer == OBSERVER_KERNELMARKERS) {
    if (!before(p, "pthread_threadid_np", 0, 0, 0))
      return 74;
    int error = pthread_threadid_np(NULL, &owner_tid);
    fact(p, "pthread_threadid_np", "return", error, owner_tid, 0, 0);
    if (error != 0)
      return 71;
  }
  p->observer = (struct observer){.timebase = p->timebase,
                                  .phase = spec->name,
                                  .memory = p->memory,
                                  .vcpu = p->vcpu,
                                  .kind = spec->observer,
                                  .owner_tid = owner_tid,
                                  .markers = p->markers,
                                  .stop = &p->observer_stop};
  if (spec->observer == OBSERVER_KERNELMARKERS)
    atomic_init(&p->observer_stop, false);
  pthread_t thread;
  if (!before(p, "pthread_create", 0, 0, 0))
    return 74;
  int created = pthread_create(&thread, NULL, observe_sentinel, &p->observer);
  p->observer_active = created == 0;
  fact(p, "pthread_create", "return", created, 0, 0, 0);
  if (created != 0)
    return 71;
  int result = run_once(p, spec);
  if (spec->observer == OBSERVER_KERNELMARKERS)
    atomic_store_explicit(&p->observer_stop, true, memory_order_release);
  // After an actual API return, run_return_ready precedes this join.
  // Early errors also join before memory or vCPU cleanup.
  before(p, "pthread_join", 0, 0, 0);
  void *thread_result = NULL;
  int joined = pthread_join(thread, &thread_result);
  fact(p, "pthread_join", "return", joined, 0, 0, 0);
  if (joined != 0)
    return 71;
  p->observer_active = false;
  fact(p, "observer_result", "fact", (int)(uintptr_t)thread_result, 0, 0, 0);
  return result != 0 ? result : (int)(uintptr_t)thread_result;
}

static int execute(struct probe *p, int target, const struct phase_case *spec) {
  p->phase = "capabilities";
  TRY(capabilities(p));
  if (target == 0)
    return 0;
  p->phase = "vm";
  hv_return_t result = CALL(p, "hv_vm_create", hv_vm_create(spec->vm_flags),
                            spec->vm_flags, 0, 0);
  p->vm_created = result == HV_SUCCESS;
  TRY(status(p, result));
  if (target == 1)
    return 0;
  p->phase = "vcpu";
  size_t memory_bytes = p->paging->memory_bytes;
  if (!before(p, "mmap", memory_bytes, PROT_READ | PROT_WRITE, 0))
    return 74;
  p->memory = mmap(NULL, memory_bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
  int error = p->memory == MAP_FAILED ? errno : 0;
  fact(p, "mmap", "return", error, memory_bytes, PROT_READ | PROT_WRITE, 0);
  if (p->memory == MAP_FAILED) {
    p->memory = NULL;
    return 71;
  }
  memcpy(p->memory + CODE, p->profile->mov, p->profile->mov_length);
  memcpy(p->memory + CODE + p->profile->mov_length, p->guest->tail,
         sizeof(p->guest->tail));
  memcpy(p->memory + GDT, p->profile->gdt, sizeof(p->profile->gdt));
  memcpy(p->memory + TSS, p->profile->tss, sizeof(p->profile->tss));
  if (p->paging->cr3 != 0) {
    memcpy(p->memory + PAGE_DIRECTORY, page_directory, sizeof(page_directory));
    memcpy(p->memory + PAGE_TABLE, page_table, sizeof(page_table));
  }
  result =
      CALL(p, "hv_vm_map",
           hv_vm_map(p->memory, 0, memory_bytes,
                     HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
           0, memory_bytes, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
  p->mapped = result == HV_SUCCESS;
  TRY(status(p, result));
  result = CALL(p, "hv_vcpu_create", hv_vcpu_create(&p->vcpu, HV_VCPU_DEFAULT),
                HV_VCPU_DEFAULT, 0, 0);
  p->cpu_created = result == HV_SUCCESS;
  TRY(status(p, result));
  if (target == 2)
    return 0;
  p->phase = "configure";
  TRY(capabilities(p));
  TRY(configure(p, spec));
  if (target == 3)
    return 0;
  p->phase = spec->name;
  if (spec->observer == OBSERVER_KERNELMARKERS)
    TRY(prepare_kernel_markers(p));
  TRY(prepare_run(p, spec->armed));
  if (spec->mtf_phase)
    return run_mtf(p, spec);
  return spec->observer != OBSERVER_NONE ? watched_run(p, spec)
                                         : run_once(p, spec);
}

static int cleanup(struct probe *p) {
  p->phase = "cleanup";
  p->cleaning = true;
  if (p->observer_active) {
    fact(p, "cleanup_blocked_observer_not_joined", "fact", 71, 0, 0, 0);
    return 71;
  }
  // Stop after a failed teardown API. Retain dependent mappings for process
  // exit.
  if (p->cpu_created) {
    hv_return_t rc =
        CALL(p, "hv_vcpu_destroy", hv_vcpu_destroy(p->vcpu), p->vcpu, 0, 0);
    if (rc != HV_SUCCESS)
      return 70;
    p->cpu_created = false;
  }
  if (p->mapped) {
    hv_return_t rc =
        CALL(p, "hv_vm_unmap", hv_vm_unmap(0, p->paging->memory_bytes), 0,
             p->paging->memory_bytes, 0);
    if (rc != HV_SUCCESS)
      return 70;
    p->mapped = false;
  }
  if (p->vm_created) {
    hv_return_t rc = CALL(p, "hv_vm_destroy", hv_vm_destroy(), 0, 0, 0);
    if (rc != HV_SUCCESS)
      return 70;
    p->vm_created = false;
  }
  if (p->memory) {
    before(p, "munmap", p->paging->memory_bytes, 0, 0);
    int rc = munmap(p->memory, p->paging->memory_bytes);
    fact(p, "munmap", "return", rc == 0 ? 0 : errno, p->paging->memory_bytes, 0,
         0);
    if (rc != 0)
      return 71;
    p->memory = NULL;
  }
  if (p->markers) {
    if (p->marker_locked) {
      before(p, "kernel_marker_munlock", PAGE_BYTES, 0, 0);
      int rc = munlock(p->markers, PAGE_BYTES);
      fact(p, "kernel_marker_munlock", "return", rc == 0 ? 0 : errno,
           PAGE_BYTES, 0, 0);
      if (rc != 0)
        return 71;
      p->marker_locked = false;
    }
    before(p, "kernel_marker_munmap", PAGE_BYTES, 0, 0);
    int rc = munmap(p->markers, PAGE_BYTES);
    fact(p, "kernel_marker_munmap", "return", rc == 0 ? 0 : errno, PAGE_BYTES,
         0, 0);
    if (rc != 0)
      return 71;
    p->markers = NULL;
  }
  fact(p, "cleanup_complete", "fact", 0, 0, 0, 0);
  return 0;
}

int main(int argc, char **argv) {
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    return 71;
  const struct phase_case phases[] = {
      {.name = "capabilities"},
      {.name = "vm"},
      {.name = "vcpu"},
      {.name = "configure"},
      {.name = "run"},
      {.name = "armed-control", .armed = true, .control = true},
      {.name = "armed-run", .armed = true},
      {.name = "armed-cpuid", .guest = GUEST_CPUID, .armed = true},
      {.name = "armed-spin", .guest = GUEST_SPIN, .armed = true},
      {.name = "armed-hlt-watch", .armed = true, .observer = OBSERVER_SENTINEL},
      {.name = "armed-hlt-forever", .armed = true, .forever = true},
      {.name = "armed-hlt-threadinfo",
       .armed = true,
       .observer = OBSERVER_THREADINFO},
      {.name = "armed-cpuid-threadinfo",
       .guest = GUEST_CPUID,
       .armed = true,
       .observer = OBSERVER_THREADINFO},
      {.name = "armed-hlt-interrupt",
       .armed = true,
       .observer = OBSERVER_INTERRUPT},
      {.name = "armed-cpuid-interrupt",
       .guest = GUEST_CPUID,
       .armed = true,
       .observer = OBSERVER_INTERRUPT},
      {.name = "armed-sti-hlt", .guest = GUEST_STI_HLT, .armed = true},
      {.name = "armed-protected32-cpuid",
       .guest = GUEST_CPUID,
       .mode = PROTECTED32,
       .armed = true},
      {.name = "armed-protected32-hlt", .mode = PROTECTED32, .armed = true},
      {.name = "armed-protected32-nopaging-cpuid",
       .guest = GUEST_CPUID,
       .mode = PROTECTED32,
       .paging = PAGING_DISABLED,
       .armed = true},
      {.name = "armed-protected32-nopaging-hlt",
       .mode = PROTECTED32,
       .paging = PAGING_DISABLED,
       .observer = OBSERVER_SENTINEL,
       .armed = true},
      {.name = "armed-protected32-paging-cpuid",
       .guest = GUEST_CPUID,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .armed = true},
      {.name = "armed-protected32-paging-hlt",
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .observer = OBSERVER_SENTINEL,
       .armed = true},
      {.name = "armed-protected32-paging-cpuid-kernelmarkers",
       .guest = GUEST_CPUID,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .observer = OBSERVER_KERNELMARKERS,
       .armed = true},
      {.name = "armed-protected32-paging-hlt-kernelmarkers",
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .observer = OBSERVER_KERNELMARKERS,
       .armed = true},
      {.name = "armed-protected32-paging-cpuid-accel-kernelmarkers",
       .guest = GUEST_CPUID,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .observer = OBSERVER_KERNELMARKERS,
       .vm_flags = HV_VM_ACCEL_APIC,
       .armed = true},
      {.name = "armed-protected32-paging-hlt-accel-kernelmarkers",
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .observer = OBSERVER_KERNELMARKERS,
       .vm_flags = HV_VM_ACCEL_APIC,
       .armed = true},
      {.name = "armed-protected32-paging-cpuid-cr8-kernelmarkers",
       .guest = GUEST_CPUID,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .observer = OBSERVER_KERNELMARKERS,
       .armed = true,
       .cr8_exits = true},
      {.name = "armed-protected32-paging-hlt-cr8-kernelmarkers",
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .observer = OBSERVER_KERNELMARKERS,
       .armed = true,
       .cr8_exits = true},
      {.name = "protected32-paging-spin-cr8-timer",
       .guest = GUEST_SPIN,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true},
      {.name = "protected32-paging-hlt-cr8-timer",
       .guest = GUEST_HLT_TIMER,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true},
      {.name = "mtf-mov",
       .guest = GUEST_HLT_TIMER,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true,
       .mtf_phase = 1},
      {.name = "mtf-hlt-observe",
       .guest = GUEST_HLT_TIMER,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true,
       .mtf_phase = 2},
      {.name = "mtf-forever-mov",
       .guest = GUEST_HLT_TIMER,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true,
       .forever = true,
       .mtf_phase = 1},
      {.name = "mtf-forever-hlt-observe",
       .guest = GUEST_HLT_TIMER,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true,
       .forever = true,
       .mtf_phase = 2},
      {.name = "mtf-nop-observe",
       .guest = GUEST_MTF_NOP,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true,
       .mtf_phase = 4},
      {.name = "mtf-hlt-resume",
       .guest = GUEST_HLT_TIMER,
       .mode = PROTECTED32,
       .paging = PAGING_ENABLED,
       .cr8_exits = true,
       .timer_only = true,
       .mtf_phase = 3},
  };
  int target = -1;
  if (argc == 2)
    for (size_t i = 0; i < sizeof(phases) / sizeof(phases[0]); ++i)
      if (strcmp(argv[1], phases[i].name) == 0)
        target = (int)i;
  if (target < 0) {
    fprintf(stderr,
            "usage: %s "
            "capabilities|vm|vcpu|configure|run|armed-control|armed-run|"
            "armed-cpuid|armed-spin|armed-hlt-watch|armed-hlt-forever|"
            "armed-hlt-threadinfo|armed-cpuid-threadinfo|"
            "armed-hlt-interrupt|armed-cpuid-interrupt|armed-sti-hlt|"
            "armed-protected32-cpuid|armed-protected32-hlt|"
            "armed-protected32-nopaging-cpuid|armed-protected32-nopaging-hlt|"
            "armed-protected32-paging-cpuid|armed-protected32-paging-hlt|"
            "armed-protected32-paging-cpuid-kernelmarkers|"
            "armed-protected32-paging-hlt-kernelmarkers|"
            "armed-protected32-paging-cpuid-accel-kernelmarkers|"
            "armed-protected32-paging-hlt-accel-kernelmarkers|"
            "armed-protected32-paging-cpuid-cr8-kernelmarkers|"
            "armed-protected32-paging-hlt-cr8-kernelmarkers|"
            "protected32-paging-spin-cr8-timer|"
            "protected32-paging-hlt-cr8-timer|mtf-mov|mtf-hlt-observe|mtf-hlt-"
            "resume|mtf-forever-mov|mtf-forever-hlt-observe|mtf-nop-observe\n",
            argv[0]);
    return 64;
  }
  struct probe p = {.phase = "startup",
                    .guest = &guests[phases[target].guest],
                    .profile = &profiles[phases[target].mode],
                    .paging = &paging_profiles[phases[target].paging],
                    .cr8_exits = phases[target].cr8_exits,
                    .timer_only = phases[target].timer_only,
                    .mtf_phase = phases[target].mtf_phase};
  if (mach_timebase_info(&p.timebase) != KERN_SUCCESS || p.timebase.denom == 0)
    return 71;
  fact(&p, "probe_start", "fact", 0, (uint64_t)target, 0, 0);
  uint64_t owner_tid = 0;
  int owner_error = pthread_threadid_np(NULL, &owner_tid);
  fact(&p, "owner_thread_id", "fact", owner_error, owner_tid, 0, 0);
  if (owner_error != 0)
    return 71;
  int primary = execute(&p, target, &phases[target]);
  fact(&p, "phase_result", "fact", primary, (uint64_t)target, p.guest_verified,
       0);
  int cleanup_release = 0;
  if (phases[target].armed &&
      (p.vm_created || p.mapped || p.cpu_created || p.memory)) {
    p.phase = "cleanup";
    cleanup_release = gate(&p, "cleanup_ready");
  }
  int teardown = cleanup(&p);
  if (teardown != 0)
    fact(&p, "implicit_process_teardown_required", "fact", teardown,
         p.cpu_created, p.mapped, p.vm_created);
  int result = teardown != 0          ? teardown
               : cleanup_release != 0 ? cleanup_release
                                      : primary;
  if (p.output_failed)
    result = 74;
  p.phase = "complete";
  fact(&p, "process_result", "fact", result, (uint64_t)primary,
       (uint64_t)teardown, p.guest_verified);
  return p.output_failed ? 74 : result;
}
