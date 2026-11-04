#if !defined(__APPLE__)
#error This diagnostic requires macOS.
#endif

#include <errno.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <pthread/qos.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

/* XNU ac9718fb1af618d5ce8678d0dc6e8a58f252216f:
 * bsd/dev/i386/sysctl.c:918-934 uses sizeof(int) and CTLTYPE_INT.
 * bsd/kern/kern_newsysctl.c:1247-1317 defines OIDFMT as {0,4}, int kind plus format.
 */
_Static_assert(sizeof(int) == 4, "NMI sysctl payload ABI");

enum { CALIBRATION_COUNT = 50000, MAX_PLANNED_COUNT = 50000000 };

static mach_timebase_info_data_t timebase;

static bool ticks_to_ns(uint64_t ticks, uint64_t *ns) {
  __uint128_t scaled = (__uint128_t)ticks * timebase.numer / timebase.denom;
  if (scaled > UINT64_MAX)
    return false;
  *ns = (uint64_t)scaled;
  return true;
}

static bool mach_ns(uint64_t *ns) {
  return ticks_to_ns(mach_absolute_time(), ns);
}

static void cpu_relax(void) {
#if defined(__x86_64__)
  __asm__ volatile("pause");
#elif defined(__arm64__)
  __asm__ volatile("yield");
#else
#error Unsupported architecture.
#endif
}

static void pause_iterations(uint64_t count) {
  for (uint64_t i = 0; i < count; ++i)
    cpu_relax();
}

static int fail(const char *stage, int error) {
  printf("{\"event\":\"error\",\"stage\":\"%s\",\"errno\":%d}\n", stage,
         error);
  fflush(stdout);
  return 1;
}

int main(int argc, char **argv) {
  if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
    return 1;
  unsigned long delay_ms = 50;
  if (argc > 3)
    return fail("arguments", EINVAL);
  if (argc >= 2) {
    char *end = NULL;
    errno = 0;
    delay_ms = strtoul(argv[1], &end, 10);
    if (errno != 0 || argv[1][0] == '-' || end == argv[1] || *end != '\0' ||
        delay_ms > 1000)
      return fail("delay_ms", EINVAL);
  }
  const char *mode = argc == 3 ? argv[2] : "clock";
  bool iterations = strcmp(mode, "iterations") == 0;
  if (!iterations && strcmp(mode, "clock") != 0)
    return fail("mode", EINVAL);
  uid_t uid = getuid();
  uid_t euid = geteuid();
  pid_t pid = getpid();
  if (euid != 0)
    return fail("privilege", EPERM);
  if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.numer == 0 ||
      timebase.denom == 0)
    return fail("timebase", EINVAL);
  int qos_result = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
  if (qos_result != 0)
    return fail("qos", qos_result);

  int mib[CTL_MAXNAME];
  size_t mib_len = CTL_MAXNAME;
  if (sysctlnametomib("machdep.misc.nmis", mib, &mib_len) != 0)
    return fail("nametomib", errno);
  if (mib_len == 0 || mib_len > CTL_MAXNAME - 2)
    return fail("mib_size", EOVERFLOW);

  int format_mib[CTL_MAXNAME] = {0, 4};
  memcpy(format_mib + 2, mib, mib_len * sizeof(mib[0]));
  unsigned char format[4096];
  size_t format_size = sizeof(format);
  if (sysctl(format_mib, (u_int)(mib_len + 2), format, &format_size, NULL, 0) !=
      0)
    return fail("oidfmt", errno);
  if (format_size != sizeof(int) + 2)
    return fail("format_size", EINVAL);
  unsigned int kind;
  memcpy(&kind, format, sizeof(kind));
  if ((kind & CTLTYPE) != CTLTYPE_INT || (kind & CTLFLAG_RW) != CTLFLAG_RW ||
      format[sizeof(int)] != 'I' || format[sizeof(int) + 1] != '\0')
    return fail("type", EINVAL);

  int count = 0;
  size_t count_size = sizeof(count);
  if (sysctl(mib, (u_int)mib_len, &count, &count_size, NULL, 0) != 0)
    return fail("initial_read", errno);
  if (count_size != sizeof(count))
    return fail("read_size", EINVAL);
  uint64_t calibration_ns = 0, calibration_count = 0, planned_count = 0;
  if (iterations) {
    calibration_count = CALIBRATION_COUNT;
    uint64_t calibration_before = mach_absolute_time();
    pause_iterations(calibration_count);
    uint64_t calibration_after = mach_absolute_time();
    if (calibration_after <= calibration_before ||
        !ticks_to_ns(calibration_after - calibration_before, &calibration_ns) ||
        calibration_ns == 0)
      return fail("calibration_clock", EINVAL);
    __uint128_t planned =
        ((__uint128_t)delay_ms * UINT64_C(1000000) * calibration_count +
         calibration_ns - 1) /
        calibration_ns;
    if (planned > MAX_PLANNED_COUNT)
      return fail("iteration_limit", EOVERFLOW);
    planned_count = (uint64_t)planned;
  }
  unsigned char command = 0;
  if (read(STDIN_FILENO, &command, 0) != 0)
    return fail("read_warmup", errno);
  if (printf("{\"event\":\"warmup\"}\n") < 0 || fflush(stdout) != 0)
    return 1;
  uint64_t ready_ns;
  if (!mach_ns(&ready_ns))
    return fail("ready_clock", EOVERFLOW);
  if (printf("{\"event\":\"ready\",\"uid\":%ju,\"euid\":%ju,\"pid\":%jd,"
             "\"clock\":\"mach_absolute_time*timebase\",\"mach_ns\":%" PRIu64
             ",\"nmis\":%d,\"type\":%u,\"kind\":%u,\"format\":\"I\","
             "\"size\":%zu,\"newsize\":%zu,\"delay_ms\":%lu,"
             "\"qos\":\"user_interactive\",\"qos_result\":%d,"
             "\"mode\":\"%s\",\"calibration_ns\":%" PRIu64
             ",\"calibration_count\":%" PRIu64 ",\"planned_count\":%" PRIu64
             ",\"max_planned_count\":%u}\n",
             (uintmax_t)uid, (uintmax_t)euid, (intmax_t)pid, ready_ns, count,
             kind & CTLTYPE, kind, count_size, sizeof(int), delay_ms,
             qos_result, mode, calibration_ns, calibration_count, planned_count,
             MAX_PLANNED_COUNT) < 0 ||
      fflush(stdout) != 0)
    return 1;

  ssize_t received;
  do {
    received = read(STDIN_FILENO, &command, 1);
  } while (received < 0 && errno == EINTR);
  if (received == 0) {
    printf("{\"event\":\"cancelled\"}\n");
    return fflush(stdout) == 0 ? 0 : 1;
  }
  if (received < 0)
    return fail("command_read", errno);
  if (command != 'G')
    return fail("command", EINVAL);

  uint64_t received_ticks = mach_absolute_time();
  __uint128_t delay_ticks =
      ((__uint128_t)delay_ms * UINT64_C(1000000) * timebase.denom +
       timebase.numer - 1) /
      timebase.numer;
  if (delay_ticks > UINT64_MAX - received_ticks)
    return fail("deadline", EOVERFLOW);
  uint64_t scheduled_ticks = received_ticks + (uint64_t)delay_ticks;
  uint64_t received_ns, scheduled_ns;
  if (!ticks_to_ns(received_ticks, &received_ns) ||
      !ticks_to_ns(scheduled_ticks, &scheduled_ns))
    return fail("trigger_clock", EOVERFLOW);
  if (printf("{\"event\":\"trigger\",\"received_mach_ns\":%" PRIu64
             ",\"scheduled_mach_ns\":%" PRIu64 ",\"delay_ms\":%lu,"
             "\"mode\":\"%s\",\"planned_count\":%" PRIu64 "}\n",
             received_ns, scheduled_ns, delay_ms, mode, planned_count) < 0 ||
      fflush(stdout) != 0)
    return 1;
  if (iterations) {
    pause_iterations(planned_count);
  } else {
    while (mach_absolute_time() < scheduled_ticks)
      cpu_relax();
  }

  int trigger = 1;
  uint64_t before_ns;
  if (!mach_ns(&before_ns))
    return fail("before_clock", EOVERFLOW);
  if (printf("{\"event\":\"before_sysctl\",\"mach_ns\":%" PRIu64
             ",\"value\":1,\"newsize\":%zu}\n",
             before_ns, sizeof(trigger)) < 0 ||
      fflush(stdout) != 0)
    return 1;
  errno = 0;
  int result = sysctl(mib, (u_int)mib_len, NULL, NULL, &trigger, sizeof(trigger));
  int saved_errno = errno;
  uint64_t after_ns = 0;
  bool clock_valid = mach_ns(&after_ns);
  if (printf("{\"event\":\"return\",\"mach_ns\":%" PRIu64
             ",\"clock_valid\":%s,\"result\":%d,\"errno\":%d}\n",
             after_ns, clock_valid ? "true" : "false", result, saved_errno) <
          0 ||
      fflush(stdout) != 0)
    return 1;
  if (result != 0 || !clock_valid)
    return 1;

  count_size = sizeof(count);
  errno = 0;
  result = sysctl(mib, (u_int)mib_len, &count, &count_size, NULL, 0);
  saved_errno = errno;
  after_ns = 0;
  clock_valid = mach_ns(&after_ns);
  if (printf("{\"event\":\"read_count\",\"mach_ns\":%" PRIu64
             ",\"clock_valid\":%s,\"result\":%d,\"errno\":%d,"
             "\"nmis\":%d,\"size\":%zu}\n",
             after_ns, clock_valid ? "true" : "false", result, saved_errno,
             count, count_size) < 0 ||
      fflush(stdout) != 0)
    return 1;
  return result == 0 && count_size == sizeof(count) && clock_valid ? 0 : 1;
}
