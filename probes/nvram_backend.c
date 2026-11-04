#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>

static bool equal_env(const char *key, const char *expected) {
  const char *value = getenv(key);
  return value != NULL && strcmp(value, expected) == 0;
}

static bool decimal(const char *value, size_t limit) {
  if (value == NULL || value[0] < '1' || value[0] > '9' ||
      strlen(value) > limit)
    return false;
  for (size_t i = 1; value[i]; ++i)
    if (value[i] < '0' || value[i] > '9')
      return false;
  return true;
}

static bool sha(const char *value) {
  if (value == NULL || strlen(value) != 40)
    return false;
  for (size_t i = 0; i < 40; ++i)
    if (!((value[i] >= '0' && value[i] <= '9') ||
          (value[i] >= 'a' && value[i] <= 'f')))
      return false;
  return true;
}

static bool guard(bool force) {
  struct utsname name;
  char uuid[128];
  int vmm = 0;
  size_t uuid_size = sizeof(uuid), vmm_size = sizeof(vmm);
  return (!force || geteuid() == 0) && uname(&name) == 0 &&
         strcmp(name.sysname, "Darwin") == 0 &&
         strcmp(name.machine, "x86_64") == 0 &&
         equal_env("GITHUB_ACTIONS", "true") &&
         equal_env("GITHUB_REPOSITORY", "Code-Hex/vz-ci-test") &&
         equal_env("GITHUB_REF", "refs/heads/main") &&
         equal_env("GITHUB_EVENT_NAME", "workflow_dispatch") &&
         equal_env("RUNNER_ENVIRONMENT", "github-hosted") &&
         decimal(getenv("GITHUB_RUN_ID"), 20) &&
         decimal(getenv("GITHUB_RUN_ATTEMPT"), 5) &&
         sha(getenv("GITHUB_SHA")) &&
         sysctlbyname("kern.uuid", uuid, &uuid_size, NULL, 0) == 0 &&
         uuid_size > 0 && uuid_size <= sizeof(uuid) &&
         uuid[uuid_size - 1] == '\0' &&
         strcmp(uuid, "87453B1D-A163-31FA-B33B-0FB4BE78E6E8") == 0 &&
         sysctlbyname("kern.hv_vmm_present", &vmm, &vmm_size, NULL, 0) == 0 &&
         vmm_size == sizeof(vmm) && vmm == 1;
}

static bool class_name(const char *name, size_t capacity) {
  size_t n = strnlen(name, capacity);
  if (n == 0 || n == capacity)
    return false;
  for (size_t i = 0; i < n; ++i)
    if (!((name[i] >= 'a' && name[i] <= 'z') ||
          (name[i] >= 'A' && name[i] <= 'Z') ||
          (name[i] >= '0' && name[i] <= '9') || name[i] == '_'))
      return false;
  return true;
}

static void inventory(const char *target) {
  io_iterator_t iterator = IO_OBJECT_NULL;
  CFMutableDictionaryRef matching = IOServiceMatching(target);
  if (matching == NULL) {
    printf("{\"event\":\"inventory\",\"target\":\"%s\","
           "\"status\":\"matching_unavailable\"}\n",
           target);
    return;
  }
  // IOServiceGetMatchingServices consumes the matching dictionary.
  kern_return_t result =
      IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
  io_name_t names[64] = {{0}};
  unsigned count = 0, valid = 0, class_errors = 0;
  bool truncated = false;
  bool observed = result == KERN_SUCCESS && iterator != IO_OBJECT_NULL;
  if (observed) {
    io_object_t object;
    while ((object = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
      if (count == 64) {
        truncated = true;
        IOObjectRelease(object);
        break;
      }
      ++count;
      io_name_t name = {0};
      kern_return_t got_class = IOObjectGetClass(object, name);
      IOObjectRelease(object);
      if (got_class == KERN_SUCCESS && class_name(name, sizeof(name)))
        memcpy(names[valid++], name, sizeof(name));
      else
        ++class_errors;
    }
  }
  bool iterator_valid = observed && IOIteratorIsValid(iterator);
  if (iterator != IO_OBJECT_NULL)
    IOObjectRelease(iterator);
  printf("{\"event\":\"inventory\",\"target\":\"%s\","
         "\"status\":\"%s\",\"ioreturn\":%u,\"count\":%u,\"truncated\":%s,"
         "\"iterator_valid\":%s,\"class_errors\":%u,\"classes\":[",
         target,
         !observed        ? "unavailable"
         : iterator_valid ? "observed"
                          : "invalidated",
         (unsigned)(uint32_t)result, count, truncated ? "true" : "false",
         iterator_valid ? "true" : "false", class_errors);
  for (unsigned i = 0; i < valid; ++i)
    printf("%s\"%s\"", i ? "," : "", names[i]);
  puts("]}");
}

int main(int argc, char **argv) {
  if (argc != 2 ||
      (strcmp(argv[1], "inspect") != 0 && strcmp(argv[1], "force-sync") != 0)) {
    puts("{\"event\":\"guard\",\"status\":\"invalid_mode\"}");
    return 64;
  }
  bool force = strcmp(argv[1], "force-sync") == 0;
  if (!guard(force)) {
    puts("{\"event\":\"guard\",\"status\":\"rejected\"}");
    return 77;
  }
  printf("{\"event\":\"guard\",\"status\":\"passed\",\"mode\":\"%s\"}\n",
         force ? "force-sync" : "inspect");
  if (fflush(stdout) != 0)
    return 74;
  io_registry_entry_t options =
      IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options");
  io_name_t name = {0};
  kern_return_t got_class = options == IO_OBJECT_NULL
                                ? kIOReturnNotFound
                                : IOObjectGetClass(options, name);
  bool valid = got_class == KERN_SUCCESS && class_name(name, sizeof(name));
  bool conforms =
      options != IO_OBJECT_NULL && IOObjectConformsTo(options, "IODTNVRAM");
  printf("{\"event\":\"inventory\",\"target\":\"options\","
         "\"found\":%s,\"class_ioreturn\":%u,\"class_status\":\"%s\","
         "\"class\":\"%s\",\"conforms_iodtnvram\":%s}\n",
         options == IO_OBJECT_NULL ? "false" : "true",
         (unsigned)(uint32_t)got_class, valid ? "observed" : "unavailable",
         valid ? name : "", conforms ? "true" : "false");
  const char *targets[] = {"IONVRAMController", "IODTNVRAM", "IOWatchDogTimer",
                           "IOKernelDebugger"};
  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i)
    inventory(targets[i]);
  int status = 0;
  if (force) {
    if (fflush(stdout) != 0) {
      status = 74;
    } else if (options == IO_OBJECT_NULL) {
      puts("{\"event\":\"sync\",\"status\":\"options_unavailable\","
           "\"durability_verified\":false}");
      status = 69;
    } else if (!conforms) {
      puts("{\"event\":\"sync\",\"status\":\"options_type_mismatch\","
           "\"durability_verified\":false}");
      status = 69;
    } else {
      kern_return_t result = IORegistryEntrySetCFProperty(
          options, CFSTR("IONVRAM-FORCESYNCNOW-PROPERTY"),
          CFSTR("IONVRAM-FORCESYNCNOW-PROPERTY"));
      printf("{\"event\":\"sync\",\"status\":\"returned\",\"ioreturn\":%u,"
             "\"durability_verified\":false}\n",
             (unsigned)(uint32_t)result);
      if (result != KERN_SUCCESS)
        status = 70;
    }
  }
  if (options != IO_OBJECT_NULL)
    IOObjectRelease(options);
  return fflush(stdout) == 0 && !ferror(stdout) ? status : 74;
}
