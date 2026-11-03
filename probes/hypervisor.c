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
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

enum { PAGE_BYTES = 4096, CODE = 0x100, SENTINEL = 0x800, TAG = 0xa5 };

enum guest_kind { GUEST_HLT, GUEST_CPUID, GUEST_SPIN };

struct guest_case {
  uint8_t tail[2];
  uint64_t exit_reason;
  // Zero means the asynchronous exit's instruction length is not read or gated.
  uint64_t instruction_length;
  const char *verified_fact;
};

// Intel SDM vol. 2 defines HLT, NOP, CPUID and JMP encodings; vol. 3C appendix
// C defines HLT=12, CPUID=10 and VMX preemption timer=52 exit reasons.
static const struct guest_case guests[] = {
    [GUEST_HLT] = {.tail = {0xf4, 0x90},
                   .exit_reason = 12,
                   .instruction_length = 1,
                   .verified_fact = "sentinel_hlt_verified"},
    [GUEST_CPUID] = {.tail = {0x0f, 0xa2},
                     .exit_reason = 10,
                     .instruction_length = 2,
                     .verified_fact = "sentinel_cpuid_verified"},
    [GUEST_SPIN] = {.tail = {0xeb, 0xfe},
                    .exit_reason = 52,
                    .instruction_length = 0,
                    .verified_fact = "sentinel_spin_verified"},
};

struct phase_case {
  const char *name;
  enum guest_kind guest;
  bool armed, control, watch, forever;
};

struct observer {
  mach_timebase_info_data_t timebase;
  const char *phase;
  const uint8_t *memory;
  hv_vcpuid_t vcpu;
};

struct probe {
  mach_timebase_info_data_t timebase;
  const char *phase;
  const struct guest_case *guest;
  uint64_t sequence;
  uint64_t cr0_fixed0, cr0_fixed1, cr4_fixed0, cr4_fixed1;
  hv_vcpuid_t vcpu;
  uint8_t *memory;
  struct observer observer;
  bool vm_created, mapped, cpu_created, cleaning, output_failed, guest_verified;
  bool observer_active;
};

static uint64_t observer_now(const struct observer *o) {
  return (uint64_t)((__uint128_t)mach_absolute_time() * o->timebase.numer /
                    o->timebase.denom);
}

static void *observe_sentinel(void *argument) {
  const struct observer *o = argument;
  uint64_t started = observer_now(o), first_tag_ns = 0;
  const uint64_t samples[] = {100000000, 500000000};
  bool seen = false;
  for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
    int error = 0;
    uint64_t now;
    uint8_t actual;
    do {
      now = observer_now(o);
      actual = *(const volatile uint8_t *)(o->memory + SENTINEL);
      if (actual == TAG && !seen) {
        seen = true;
        first_tag_ns = now - started;
      }
      if (now - started >= samples[i])
        break;
      struct timespec delay = {.tv_nsec = 5000000};
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

static int configure(struct probe *p) {
  uint64_t applied, entry;
  // Intel SDM vol. 3C, 24.6: activate secondary controls (31), HLT exiting (7),
  // EPT (secondary 1), unrestricted guest (secondary 7). See
  // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  TRY(control(p, VMCS_CTRL_PIN_BASED, 0, 0, &applied));
  TRY(control(p, VMCS_CTRL_CPU_BASED, (1ULL << 31) | (1ULL << 7),
              (1ULL << 2) | (1ULL << 22) | (1ULL << 27), &applied));
  TRY(control(p, VMCS_CTRL_CPU_BASED2, (1ULL << 1) | (1ULL << 7), 1ULL << 14,
              &applied));
  TRY(control(p, VMCS_CTRL_VMENTRY_CONTROLS, 0,
              (1ULL << 9) | (1ULL << 10) | (1ULL << 11), &entry));
  // SDM 26.3.1: unrestricted guest relaxes CR0.PE/PG fixed-one requirements.
  uint64_t cr0 = (p->cr0_fixed0 | (1ULL << 4)) & ~((1ULL << 31) | 1ULL);
  uint64_t cr4 = p->cr4_fixed0;
  if ((cr0 & ~p->cr0_fixed1) || (cr4 & ~p->cr4_fixed1) ||
      (cr0 & ((1ULL << 29) | (1ULL << 30))) || (cr4 & (1ULL << 17))) {
    fact(p, "cr_not_established", "fact", 77, cr0, cr4, 0);
    return 77;
  }
  TRY(write_field(p, VMCS_GUEST_CR0, cr0));
  TRY(write_field(p, VMCS_GUEST_CR3, 0));
  TRY(write_field(p, VMCS_GUEST_CR4, cr4));
  const struct {
    uint32_t selector, base, limit, access;
    uint64_t rights;
  } segments[] = {
      {VMCS_GUEST_CS, VMCS_GUEST_CS_BASE, VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_AR,
       0x9b},
      {VMCS_GUEST_DS, VMCS_GUEST_DS_BASE, VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR,
       0x93},
      {VMCS_GUEST_ES, VMCS_GUEST_ES_BASE, VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR,
       0x93},
      {VMCS_GUEST_SS, VMCS_GUEST_SS_BASE, VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR,
       0x93},
      {VMCS_GUEST_FS, VMCS_GUEST_FS_BASE, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR,
       0x93},
      {VMCS_GUEST_GS, VMCS_GUEST_GS_BASE, VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR,
       0x93},
      {VMCS_GUEST_TR, VMCS_GUEST_TR_BASE, VMCS_GUEST_TR_LIMIT, VMCS_GUEST_TR_AR,
       0x8b},
      {VMCS_GUEST_LDTR, VMCS_GUEST_LDTR_BASE, VMCS_GUEST_LDTR_LIMIT,
       VMCS_GUEST_LDTR_AR, 0x10000},
  };
  // SDM 26.3 and 24.4.1 describe segment access rights and real-mode state.
  for (size_t i = 0; i < sizeof(segments) / sizeof(segments[0]); ++i) {
    TRY(write_field(p, segments[i].selector, 0));
    TRY(write_field(p, segments[i].base, 0));
    TRY(write_field(p, segments[i].limit, 0xffff));
    TRY(write_field(p, segments[i].access, segments[i].rights));
  }
  const struct {
    uint32_t field;
    uint64_t value;
  } fields[] = {
      {VMCS_GUEST_GDTR_BASE, 0},
      {VMCS_GUEST_GDTR_LIMIT, 0xffff},
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

static int gate(struct probe *p, const char *name) {
  // fflush proves only local output completion. The controller must receive
  // this named gate and independently check the runner before sending G.
  if (!fact(p, name, "fact", 0, 'G', 0, 0))
    return 74;
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
  if (command != 'G') {
    fact(p, name, "protocol_error", 64, command, 'G', 0);
    return 64;
  }
  return fact(p, name, "released", 0, command, 0, 0) ? 0 : 74;
}

static int prepare_run(struct probe *p, bool armed) {
  // Intel SDM vol. 2: C6 /0, MOV byte [disp16], imm8 precedes each case's tail.
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
  TRY(status(p, result));
  uint64_t reason = 0, rip = 0, length = 0;
  TRY(status(p,
             CALL(p, "hv_vmx_vcpu_read_vmcs",
                  hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_RO_EXIT_REASON, &reason),
                  VMCS_RO_EXIT_REASON, 0, 0)));
  TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                     hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_GUEST_RIP, &rip),
                     VMCS_GUEST_RIP, 0, 0)));
  if (p->guest->instruction_length != 0)
    TRY(status(p, CALL(p, "hv_vmx_vcpu_read_vmcs",
                       hv_vmx_vcpu_read_vmcs(p->vcpu, VMCS_RO_VMEXIT_INSTR_LEN,
                                             &length),
                       VMCS_RO_VMEXIT_INSTR_LEN, 0, 0)));
  uint8_t actual = *(volatile uint8_t *)(p->memory + SENTINEL);
  fact(p, "guest_observation", "fact", 0, actual, rip, length);
  // SDM appendix C: bit 31 marks VM-entry failure.
  bool length_matches = p->guest->instruction_length == 0 ||
                        length == p->guest->instruction_length;
  p->guest_verified = !(reason & (1ULL << 31)) &&
                      (reason & 0xffff) == p->guest->exit_reason &&
                      actual == TAG && rip == CODE + 5 && length_matches;
  fact(p, p->guest_verified ? p->guest->verified_fact : "guest_not_established",
       "fact", p->guest_verified ? 0 : 77, reason, rip, length);
  return p->guest_verified ? 0 : 77;
}

static int watched_run(struct probe *p, const struct phase_case *spec) {
  p->observer = (struct observer){.timebase = p->timebase,
                                  .phase = spec->name,
                                  .memory = p->memory,
                                  .vcpu = p->vcpu};
  pthread_t thread;
  if (!before(p, "pthread_create", 0, 0, 0))
    return 74;
  int created = pthread_create(&thread, NULL, observe_sentinel, &p->observer);
  p->observer_active = created == 0;
  fact(p, "pthread_create", "return", created, 0, 0, 0);
  if (created != 0)
    return 71;
  int result = run_once(p, spec);
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
  hv_return_t result =
      CALL(p, "hv_vm_create", hv_vm_create(HV_VM_DEFAULT), HV_VM_DEFAULT, 0, 0);
  p->vm_created = result == HV_SUCCESS;
  TRY(status(p, result));
  if (target == 1)
    return 0;
  p->phase = "vcpu";
  if (!before(p, "mmap", PAGE_BYTES, PROT_READ | PROT_WRITE, 0))
    return 74;
  p->memory = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
  int error = p->memory == MAP_FAILED ? errno : 0;
  fact(p, "mmap", "return", error, PAGE_BYTES, PROT_READ | PROT_WRITE, 0);
  if (p->memory == MAP_FAILED) {
    p->memory = NULL;
    return 71;
  }
  const uint8_t code[] = {
      0xc6, 0x06, 0x00, 0x08, TAG, p->guest->tail[0], p->guest->tail[1]};
  memcpy(p->memory + CODE, code, sizeof(code));
  result =
      CALL(p, "hv_vm_map",
           hv_vm_map(p->memory, 0, PAGE_BYTES,
                     HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
           0, PAGE_BYTES, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
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
  TRY(configure(p));
  if (target == 3)
    return 0;
  p->phase = spec->name;
  TRY(prepare_run(p, spec->armed));
  return spec->watch ? watched_run(p, spec) : run_once(p, spec);
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
        CALL(p, "hv_vm_unmap", hv_vm_unmap(0, PAGE_BYTES), 0, PAGE_BYTES, 0);
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
    before(p, "munmap", PAGE_BYTES, 0, 0);
    int rc = munmap(p->memory, PAGE_BYTES);
    fact(p, "munmap", "return", rc == 0 ? 0 : errno, PAGE_BYTES, 0, 0);
    if (rc != 0)
      return 71;
    p->memory = NULL;
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
      {.name = "armed-hlt-watch", .armed = true, .watch = true},
      {.name = "armed-hlt-forever", .armed = true, .forever = true},
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
            "armed-cpuid|armed-spin|armed-hlt-watch|armed-hlt-forever\n",
            argv[0]);
    return 64;
  }
  struct probe p = {.phase = "startup", .guest = &guests[phases[target].guest]};
  if (mach_timebase_info(&p.timebase) != KERN_SUCCESS || p.timebase.denom == 0)
    return 71;
  fact(&p, "probe_start", "fact", 0, (uint64_t)target, 0, 0);
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
