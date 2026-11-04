#include <errno.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__x86_64__)
extern const char poststop_loop_begin[];
extern const char poststop_loop_end[];

/* The constants are register values, never addresses to dereference. */
__attribute__((naked, noinline))
static void register_loop(uint64_t iterations __attribute__((unused)))
{
    __asm__ volatile(
        "pushq %rbp\n"
        "pushq %rbx\n"
        "movq %rdi, %rcx\n"
        "movabsq $0x1122334455667788, %rbp\n"
        "movabsq $0x8877665544332211, %rbx\n"
        ".globl _poststop_loop_begin\n"
        "_poststop_loop_begin:\n"
        "pause\n"
        "decq %rcx\n"
        "jnz _poststop_loop_begin\n"
        ".globl _poststop_loop_end\n"
        "_poststop_loop_end:\n"
        "popq %rbx\n"
        "popq %rbp\n"
        "retq\n");
}
#endif

int main(int argc, char **argv)
{
#if !defined(__x86_64__)
    (void)argc;
    (void)argv;
    fputs("x86_64 required\n", stderr);
    return 77;
#else
    uint64_t iterations = UINT64_C(50000000);
    if (argc > 2) {
        fputs("usage: poststop-register-control [iterations]\n", stderr);
        return 2;
    }
    if (argc == 2) {
        char *end = NULL;
        errno = 0;
        unsigned long long parsed = strtoull(argv[1], &end, 10);
        if (errno != 0 || argv[1][0] < '0' || argv[1][0] > '9' ||
            end == argv[1] || *end != '\0' || parsed == 0 ||
            parsed > UINT64_C(1000000000)) {
            fputs("iterations must be 1..1000000000\n", stderr);
            return 2;
        }
        iterations = (uint64_t)parsed;
    }
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) {
        fputs("mach_timebase_info failed\n", stderr);
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"type\":\"ready\",\"pid\":%d,\"loop_begin\":%" PRIuPTR
           ",\"loop_end\":%" PRIuPTR ",\"expected_rbp\":%" PRIu64
           ",\"expected_rbx\":%" PRIu64 ",\"iterations\":%" PRIu64
           ",\"timebase_numer\":%u,\"timebase_denom\":%u}\n",
           getpid(), (uintptr_t)poststop_loop_begin,
           (uintptr_t)poststop_loop_end, UINT64_C(0x1122334455667788),
           UINT64_C(0x8877665544332211), iterations,
           timebase.numer, timebase.denom);
    int gate;
    do {
        gate = getchar();
    } while (gate == '\n' || gate == '\r');
    if (gate != 'G') {
        fputs("expected G on stdin\n", stderr);
        return 2;
    }
    uint64_t before = mach_absolute_time();
    register_loop(iterations);
    uint64_t after = mach_absolute_time();
    uint64_t elapsed_ns = (uint64_t)(((__uint128_t)(after - before) *
                                     timebase.numer) / timebase.denom);
    printf("{\"type\":\"done\",\"pid\":%d,\"mach_before_ticks\":%" PRIu64
           ",\"mach_after_ticks\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 "}\n",
           getpid(), before, after, elapsed_ns);
    return 0;
#endif
}
