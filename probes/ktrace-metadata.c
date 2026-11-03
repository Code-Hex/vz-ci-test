#include <dlfcn.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

enum { CODE_BYTES = 128 };

static int describe_symbol(void *library, const char *name) {
  dlerror();
  void *symbol = dlsym(library, name);
  const char *error = dlerror();
  if (error || !symbol) {
    fprintf(stderr, "symbol=%s dlsym_error=%s\n", name,
            error ? error : "null address");
    return 1;
  }
#if __has_feature(ptrauth_calls)
  symbol = ptrauth_strip(symbol, ptrauth_key_function_pointer);
#endif

  Dl_info info = {0};
  if (!dladdr(symbol, &info)) {
    fprintf(stderr, "symbol=%s dladdr_failed=1\n", name);
    return 1;
  }

  uint8_t code[CODE_BYTES] = {0};
  mach_vm_size_t copied = 0;
  // Read only our own mapping. Never invoke the resolved private function.
  kern_return_t result = mach_vm_read_overwrite(
      mach_task_self(), (mach_vm_address_t)(uintptr_t)symbol, sizeof(code),
      (mach_vm_address_t)(uintptr_t)code, &copied);
  printf("symbol=%s address=0x%" PRIxPTR " image_base=0x%" PRIxPTR
         " image_offset=0x%" PRIxPTR " image=%s read_result=%d bytes=%" PRIu64
         " hex=",
         name, (uintptr_t)symbol, (uintptr_t)info.dli_fbase,
         (uintptr_t)symbol - (uintptr_t)info.dli_fbase,
         info.dli_fname ? info.dli_fname : "(unknown)", result,
         (uint64_t)copied);
  if (result == KERN_SUCCESS && copied <= sizeof(code)) {
    for (mach_vm_size_t i = 0; i < copied; i++)
      printf("%02x", code[i]);
  }
  putchar('\n');
  return result != KERN_SUCCESS || copied != sizeof(code);
}

int main(void) {
  const char *path =
      "/System/Library/PrivateFrameworks/ktrace.framework/Versions/A/ktrace";
  const char *symbols[] = {"ktrace_set_collection_interval", "ktrace_start",
                           "ktrace_set_signal_handler"};
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("library=%s\n", path);
  void *library = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
  if (!library) {
    fprintf(stderr, "dlopen_error=%s\n", dlerror());
    return 1;
  }
  int failed = 0;
  for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++)
    failed |= describe_symbol(library, symbols[i]);
  if (dlclose(library) != 0) {
    fprintf(stderr, "dlclose_error=%s\n", dlerror());
    failed = 1;
  }
  if (ferror(stdout))
    failed = 1;
  return failed;
}
