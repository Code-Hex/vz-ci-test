#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

_Static_assert(RB_QUICK == 0x400 && RB_PANIC == 0x800 &&
                   RB_PANIC_FORCERESET == 0x2000,
               "unexpected XNU reboot flags");

typedef int (*reboot_np_fn)(int, const char *);

static bool equal_env(const char *name, const char *expected) {
  const char *value = getenv(name);
  return value != NULL && strcmp(value, expected) == 0;
}

static bool decimal(const char *value, size_t limit) {
  if (value == NULL || value[0] < '1' || value[0] > '9')
    return false;
  size_t n = strlen(value);
  if (n > limit)
    return false;
  for (size_t i = 1; i < n; ++i)
    if (value[i] < '0' || value[i] > '9')
      return false;
  return true;
}

static bool lowercase_hex(const char *value, size_t length) {
  if (value == NULL || strlen(value) != length)
    return false;
  for (size_t i = 0; i < length; ++i)
    if (!((value[i] >= '0' && value[i] <= '9') ||
          (value[i] >= 'a' && value[i] <= 'f')))
      return false;
  return true;
}

static bool sysctl_string_equals(const char *key, const char *expected) {
  char buffer[128];
  size_t length = sizeof(buffer);
  if (sysctlbyname(key, buffer, &length, NULL, 0) != 0 || length == 0 ||
      length > sizeof(buffer) || buffer[length - 1] != '\0')
    return false;
  return strcmp(buffer, expected) == 0;
}

static bool guard(void) {
  struct utsname name;
  int vmm = 0;
  size_t size = sizeof(vmm);
  const char *baseline = getenv("VZ_RECOVERY_BOOT_UUID");
  if (geteuid() != 0 || uname(&name) != 0 || strcmp(name.sysname, "Darwin") ||
      strcmp(name.machine, "x86_64") ||
      !equal_env("GITHUB_ACTIONS", "true") ||
      !equal_env("GITHUB_EVENT_NAME", "workflow_dispatch") ||
      !equal_env("GITHUB_REPOSITORY", "Code-Hex/vz-ci-test") ||
      !equal_env("GITHUB_REF", "refs/heads/main") ||
      !equal_env("RUNNER_ENVIRONMENT", "github-hosted") ||
      !equal_env("RECOVERY_TRIGGER", "panic-force-reset") ||
      !decimal(getenv("GITHUB_RUN_ID"), 20) ||
      !decimal(getenv("GITHUB_RUN_ATTEMPT"), 5) ||
      !lowercase_hex(getenv("GITHUB_SHA"), 40) ||
      !lowercase_hex(getenv("VZ_RECOVERY_NONCE"), 64) || baseline == NULL ||
      !sysctl_string_equals("kern.uuid", "87453B1D-A163-31FA-B33B-0FB4BE78E6E8") ||
      !sysctl_string_equals("kern.bootsessionuuid", baseline) ||
      sysctlbyname("kern.hv_vmm_present", &vmm, &size, NULL, 0) != 0 ||
      size != sizeof(vmm) || vmm != 1)
    return false;
  return true;
}

int main(int argc, char **argv) {
  if (argc != 2 || (strcmp(argv[1], "preflight") && strcmp(argv[1], "execute")))
    return 64;
  if (!guard()) {
    fputs("{\"event\":\"force_reset_guard_failed\"}\n", stderr);
    return 77;
  }
  void *symbol = dlsym(RTLD_DEFAULT, "reboot_np");
  if (symbol == NULL) {
    fputs("{\"event\":\"force_reset_symbol_unavailable\"}\n", stderr);
    return 77;
  }
  reboot_np_fn call = NULL;
  _Static_assert(sizeof(call) == sizeof(symbol), "function pointer size");
  memcpy(&call, &symbol, sizeof(call));
  if (strcmp(argv[1], "preflight") == 0) {
    puts("{\"event\":\"force_reset_preflight\",\"symbol_available\":true,"
         "\"flags\":11264,\"entitlement_verified\":false}");
    return 0;
  }
  char marker[160];
  int n = snprintf(marker, sizeof(marker), "vz-force-reset:%s:%s:%s",
                   getenv("GITHUB_RUN_ID"), getenv("GITHUB_RUN_ATTEMPT"),
                   getenv("VZ_RECOVERY_NONCE"));
  if (n < 0 || (size_t)n >= sizeof(marker))
    return 77;
  errno = 0;
  int result = call(RB_QUICK | RB_PANIC | RB_PANIC_FORCERESET, marker);
  int error = errno;
  fprintf(stderr, "{\"event\":\"force_reset_unexpected_return\","
                  "\"result\":%d,\"errno\":%d}\n", result, error);
  return 70;
}
