#pragma D option quiet
#pragma D option bufpolicy=fill
#pragma D option bufsize=1m
#pragma D option dynvarsize=1m

/* dtrace -C -s poststop-frame-control.d PID LOOP_BEGIN LOOP_END
 * Requires this runner's CTF preflight. Read only the current CPU's frame.
 * RBX/RBP sentinel values are compared as integers, never dereferenced.
 */
uint64_t sample[uint32_t, uint32_t];
uint64_t seen[uint32_t];
uint64_t valid[uint32_t];
uint64_t mismatch[uint32_t];

profile-997
/pid == $1 && cpu < 4 && arg1 >= $2 && arg1 < $3/
{
    this->start = timestamp;
    this->cdp = ((struct cpu_data **)&`cpu_data_ptr)[cpu];
    this->frame = this->cdp == 0 ? (x86_saved_state_t *)0 :
        (x86_saved_state_t *)this->cdp->cpu_int_state;
    this->flavor = this->frame == 0 ? 0 : this->frame->flavor;
    this->rip = this->flavor == 15 ? this->frame->uss.ss_64.isf.rip : 0;
    this->rbp = this->flavor == 15 ? this->frame->uss.ss_64.rbp : 0;
    this->rbx = this->flavor == 15 ? this->frame->uss.ss_64.rbx : 0;
    this->rsp = this->flavor == 15 ? this->frame->uss.ss_64.isf.rsp : 0;
    this->cs = this->flavor == 15 ? this->frame->uss.ss_64.isf.cs : 0;
    this->flags = this->flavor == 15 ? this->frame->uss.ss_64.isf.rflags : 0;
    this->ok = this->frame != 0 && this->flavor == 15 &&
        this->rip == arg1 && (this->cs & 3) == 3 &&
        this->rbp == 0x1122334455667788ULL &&
        this->rbx == 0x8877665544332211ULL;
    seen[cpu] = seen[cpu] + 1;
    valid[cpu] = valid[cpu] + this->ok;
    mismatch[cpu] = mismatch[cpu] + !this->ok;
    sample[cpu, 0] = this->start;
    sample[cpu, 2] = (uint64_t)tid;
    sample[cpu, 3] = (uint64_t)this->frame;
    sample[cpu, 4] = this->flavor;
    sample[cpu, 5] = arg0;
    sample[cpu, 6] = arg1;
    sample[cpu, 7] = this->rip;
    sample[cpu, 8] = this->rbp;
    sample[cpu, 9] = this->rbx;
    sample[cpu, 10] = this->rsp;
    sample[cpu, 11] = this->cs;
    sample[cpu, 12] = this->flags;
    sample[cpu, 13] = ((struct thread *)curthread)->kernel_stack;
}

profile-997
/pid == $1 && cpu >= 4/
{
    out_of_range = 1;
}

dtrace:::ERROR
{
    errors = 1;
}

tick-10s
{
    exit(0);
}

#define CONTROL_CPU(c) \
dtrace:::END \
{ \
    printf("{\"type\":\"cpu\",\"cpu\":%u,\"seen\":%llu,\"valid\":%llu,\"mismatch\":%llu,\"sample_timestamp_ns\":%llu,\"age_at_end_ns\":%llu,\"tid\":%llu,\"frame\":%llu,\"flavor\":%llu,\"kernel_pc\":%llu,\"user_pc\":%llu,\"rip\":%llu,\"rbp\":%llu,\"rbx\":%llu,\"rsp\":%llu,\"cs\":%llu,\"rflags\":%llu,\"kernel_stack\":%llu}\n", \
        c, seen[c], valid[c], mismatch[c], sample[c, 0], \
        seen[c] == 0 ? 0 : timestamp - sample[c, 0], \
        sample[c, 2], sample[c, 3], sample[c, 4], sample[c, 5], sample[c, 6], \
        sample[c, 7], sample[c, 8], sample[c, 9], sample[c, 10], \
        sample[c, 11], sample[c, 12], sample[c, 13]); \
}

CONTROL_CPU(0)
CONTROL_CPU(1)
CONTROL_CPU(2)
CONTROL_CPU(3)

dtrace:::END
{
    printf("{\"type\":\"summary\",\"pid\":%u,\"loop_begin\":%llu,\"loop_end\":%llu,\"seen\":%llu,\"valid\":%llu,\"mismatch\":%llu,\"error_seen\":%llu,\"out_of_range_cpu\":%llu}\n",
        $1, (uint64_t)$2, (uint64_t)$3,
        seen[0] + seen[1] + seen[2] + seen[3],
        valid[0] + valid[1] + valid[2] + valid[3],
        mismatch[0] + mismatch[1] + mismatch[2] + mismatch[3],
        (uint64_t)errors, (uint64_t)out_of_range);
}
