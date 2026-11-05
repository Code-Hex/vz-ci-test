#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>

_Static_assert(RB_QUICK == 0x400 && RB_PANIC == 0x800,
               "unexpected reboot flags");
typedef int (*reboot_fn)(int, const char *);

static bool env_equals(const char *key, const char *value) {
  const char *actual = getenv(key);
  return actual && strcmp(actual, value) == 0;
}
static bool decimal(const char *s, size_t maximum) {
  if (!s || s[0] < '1' || s[0] > '9' || strlen(s) > maximum)
    return false;
  for (size_t i = 1; s[i]; ++i)
    if (s[i] < '0' || s[i] > '9')
      return false;
  return true;
}
static bool hex(const char *s, size_t n) {
  if (!s || strlen(s) != n)
    return false;
  for (size_t i = 0; i < n; ++i)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}
static bool uuid(const char *s) {
  if (!s || strlen(s) != 36)
    return false;
  for (size_t i = 0; i < 36; ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (s[i] != '-')
        return false;
    } else if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'F')))
      return false;
  }
  return true;
}
static bool sysctl_equals(const char *key, const char *expected) {
  char value[128];
  size_t n = sizeof(value);
  return sysctlbyname(key, value, &n, NULL, 0) == 0 && n > 0 &&
         n <= sizeof(value) && value[n - 1] == '\0' &&
         strcmp(value, expected) == 0;
}
static bool guard(void) {
  struct utsname u;
  int vmm = 0;
  size_t n = sizeof(vmm);
  const char *boot = getenv("VZ_RECOVERY_BOOT_UUID");
  return geteuid() == 0 && uname(&u) == 0 && !strcmp(u.sysname, "Darwin") &&
         !strcmp(u.machine, "x86_64") && env_equals("GITHUB_ACTIONS", "true") &&
         env_equals("GITHUB_REPOSITORY", "Code-Hex/vz-ci-test") &&
         env_equals("GITHUB_REF", "refs/heads/main") &&
         env_equals("GITHUB_EVENT_NAME", "workflow_dispatch") &&
         env_equals("RUNNER_ENVIRONMENT", "github-hosted") &&
         env_equals("RECOVERY_TRIGGER", "reboot-quick") &&
         env_equals("RECOVERY_AFTER_DEBUG_BOOT", "panic-nonce-syscall") &&
         env_equals("RECOVERY_DEBUG_SOURCE", "bootplist") &&
         env_equals("RECOVERY_DEBUG_BOOT", "true") &&
         decimal(getenv("GITHUB_RUN_ID"), 20) &&
         decimal(getenv("GITHUB_RUN_ATTEMPT"), 5) &&
         hex(getenv("GITHUB_SHA"), 40) &&
         hex(getenv("VZ_RECOVERY_NONCE"), 64) && uuid(boot) &&
         sysctl_equals("kern.uuid", "87453B1D-A163-31FA-B33B-0FB4BE78E6E8") &&
         sysctl_equals("kern.bootsessionuuid", boot) &&
         sysctlbyname("kern.hv_vmm_present", &vmm, &n, NULL, 0) == 0 &&
         n == sizeof(vmm) && vmm == 1;
}
int main(int argc, char **argv) {
  (void)argv;
  if (argc != 1 || !guard()) {
    fputs("REBOOT_GUARD_FAILED\n", stderr);
    return 77;
  }
  void *symbol = dlsym(RTLD_DEFAULT, "reboot_np");
  reboot_fn call;
  _Static_assert(sizeof(call) == sizeof(symbol), "function pointer size");
  if (!symbol) {
    fputs("REBOOT_SYMBOL_UNAVAILABLE\n", stderr);
    return 77;
  }
  memcpy(&call, &symbol, sizeof(call));
  char marker[128];
  int n = snprintf(marker, sizeof(marker), "vz-reboot-panic:%s:%ld",
                   getenv("VZ_RECOVERY_NONCE"), (long)getpid());
  if (n <= 0 || (size_t)n >= sizeof(marker))
    return 77;
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("REBOOT_READY %ld %s\n", (long)getpid(), marker);
  char input;
  ssize_t count;
  do {
    count = read(STDIN_FILENO, &input, 1);
  } while (count < 0 && errno == EINTR);
  if (count != 1)
    return 65;
  if (input == 'Q')
    return 0;
  if (input != 'G')
    return 65;
  errno = 0;
  int result = call(RB_QUICK | RB_PANIC, marker);
  int error = errno;
  printf("REBOOT_RETURNED %d %d\n", result, error);
  return 70;
}
