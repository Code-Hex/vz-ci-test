#pragma D option quiet
#pragma D option bufpolicy=fill
#pragma D option bufsize=1m
#pragma D option dynvarsize=1m

/* dtrace -C -w -s pc_sampler.d HELPER_PID PAGE_ADDRESS DEDICATED_FD
 * Intel-only DIF/TSO publication. This is a latest-sample snapshot,
 * not a complete trace.
 */

uint64_t value[uint32_t, uint32_t];
uint64_t sequence[uint32_t];

#define PC_INIT(c) \
    value[c, 0] = 1; value[c, 1] = 1; value[c, 2] = 1; \
    value[c, 3] = 1; value[c, 4] = 1; sequence[c] = 2;

dtrace:::BEGIN
{
    PC_INIT(0)
    PC_INIT(1)
    PC_INIT(2)
    PC_INIT(3)
}

profile-997
/cpu < 4 && arg0 != 0xffffffffffffffff && arg1 != 0xffffffffffffffff/
{
    this->next = (sequence[cpu] & ~1ULL) + 2;
    sequence[cpu] = this->next - 1;
    /* Nonzero storage retains each fixed associative entry. Zero deletes it. */
    value[cpu, 0] = timestamp + 1;
    value[cpu, 1] = arg0 + 1;
    value[cpu, 2] = arg1 + 1;
    value[cpu, 3] = (uint64_t)pid + 1;
    value[cpu, 4] = (uint64_t)tid + 1;
    sequence[cpu] = this->next;
}

profile-997
/cpu >= 4/
{
    out_of_range_cpu = 1;
}

/* Each CPU has one profile writer. The export probe reads each generation twice.
 * Every LDGAA/STGAA invokes dtrace_dynvar's consumer fence in the pinned XNU
 * interpreter. Aligned uint64_t stores and Intel store order are required.
 * Reject odd, changed, missing, or regressed generations in userland.
 */
#define PC_EXPORT(c) \
syscall::write*:entry \
/pid == $1 && arg0 == $3 && arg1 == $2 && arg2 == 0/ \
{ \
    this->r = (uint64_t *)alloca(64); \
    this->r[0] = sequence[c]; \
    this->r[1] = value[c, 0] - 1; \
    this->r[2] = value[c, 1] - 1; \
    this->r[3] = value[c, 2] - 1; \
    this->r[4] = value[c, 3] - 1; \
    this->r[5] = value[c, 4] - 1; \
    this->r[6] = c; \
    this->r[7] = value[c, 0] != 0 && value[c, 1] != 0 && \
        value[c, 2] != 0 && value[c, 3] != 0 && value[c, 4] != 0 ? \
        sequence[c] : 0; \
    copyout(this->r, (uintptr_t)$2 + 32 + c * 64, 64); \
}

PC_EXPORT(0)
PC_EXPORT(1)
PC_EXPORT(2)
PC_EXPORT(3)

syscall::write*:entry
/pid == $1 && arg0 == $3 && arg1 == $2 && arg2 == 0/
{
    this->h = (uint64_t *)alloca(32);
    this->h[1] = timestamp;
    this->h[2] = out_of_range_cpu;
    this->h[3] = 0;
    copyout(this->h + 1, (uintptr_t)$2 + 8, 24);
    this->h[0] = 0x504353414d504c31ULL;
    copyout(this->h, (uintptr_t)$2, 8);
}
