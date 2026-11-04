#include "wait_snapshot.h"

#pragma D option quiet
#pragma D option bufpolicy=fill
#pragma D option bufsize=1m
#pragma D option dynvarsize=1m

/* dtrace -C -I probes -w -s probes/pc_sampler.d HELPER_PID PAGE_ADDRESS DEDICATED_FD
 * Intel-only DIF/TSO publication. This is a latest-sample snapshot,
 * not a complete trace.
 */

uint64_t value[uint32_t, uint32_t];
uint64_t sequence[uint32_t];
uint64_t wait_value[uint32_t, uint32_t];
uint64_t wait_sequence[uint32_t];
uint64_t wait_zero[uint32_t];
uint64_t wait_invalid[uint32_t];
uint64_t wait_error[uint32_t];

#define WAIT_INIT_FIELD(c, name, index) wait_value[c, index] = 1;
#define WAIT_INIT(c) \
    WAIT_FIELD_LIST(WAIT_INIT_FIELD, c) \
    wait_sequence[c] = 2; wait_zero[c] = WAIT_ZERO_MASK + 1; \
    wait_invalid[c] = 1; wait_error[c] = 1;

#define PC_INIT(c) \
    value[c, 0] = 1; value[c, 1] = 1; value[c, 2] = 1; \
    value[c, 3] = 1; value[c, 4] = 1; sequence[c] = 2;

dtrace:::BEGIN
{
    PC_INIT(0)
    PC_INIT(1)
    PC_INIT(2)
    PC_INIT(3)
    WAIT_INIT(0)
    WAIT_INIT(1)
    WAIT_INIT(2)
    WAIT_INIT(3)
    wait_slide = (uintptr_t)&`machine_idle - WAIT_UNSLID_IDLE;
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

/* Zero has a bitmap bit and storage 1. All other uint64 values are unchanged. */
#define WAIT_ZERO_FIELD(c, name, index) \
    this->zero_bits = this->zero_bits | \
        ((uint64_t)((uint64_t)this->name == 0) << index);
#define WAIT_STORE_FIELD(c, name, index) \
    wait_value[c, index] = this->ok ? \
        ((uint64_t)this->name != 0 ? (uint64_t)this->name : 1ULL) : \
        wait_value[c, index];

profile-997
/cpu < 4 && WAIT_SAFE_PC(arg0, wait_slide)/
{
    this->cdp = ((struct cpu_data **)&`cpu_data_ptr)[cpu];
    this->stage = this->cdp == 0 ? 1 : 0;
    this->active = this->stage == 0 ?
        (uintptr_t)this->cdp->cpu_active_thread : 0;
    this->stage = this->stage == 0 && this->active != (uintptr_t)curthread ?
        1 : this->stage;
    this->frame = this->stage == 0 ?
        (x86_saved_state_t *)this->cdp->cpu_int_state : (x86_saved_state_t *)0;
    this->flavor = this->frame == 0 ? 0 : this->frame->flavor;
    this->stage = this->stage == 0 && this->flavor != 15 ? 2 : this->stage;
    this->rip = this->stage == 0 ? this->frame->uss.ss_64.isf.rip : 0;
    this->rbp = this->stage == 0 ? this->frame->uss.ss_64.rbp : 0;
    this->rbx = this->stage == 0 ? this->frame->uss.ss_64.rbx : 0;
    this->rsp = this->stage == 0 ? this->frame->uss.ss_64.isf.rsp : 0;
    this->cs = this->stage == 0 ? this->frame->uss.ss_64.isf.cs : 0;
    this->flags = this->stage == 0 ? this->frame->uss.ss_64.isf.rflags : 0;
    this->stage = this->stage == 0 &&
        (this->rip != arg0 || this->cs != 8) ? 3 : this->stage;

    this->base = this->stage == 0 ?
        (uint64_t)((struct thread *)curthread)->kernel_stack : 0;
    this->size = this->stage == 0 ? (uint64_t)`kernel_stack_size : 0;
    this->top = this->base + this->size;
    this->stage = this->stage == 0 &&
        (this->base == 0 || this->size != 16384 ||
         this->top <= this->base) ? 4 : this->stage;
    this->stage = this->stage == 0 &&
        ((this->rbp & 7) != 0 || this->rbp < this->base + 0x30 ||
         this->rbp > this->top - 0x10 || this->rsp != this->rbp - 0x30) ?
        5 : this->stage;

    this->parent = this->stage == 0 ? *(uint64_t *)this->rbp : 0;
    this->return_pc = this->stage == 0 ? *(uint64_t *)(this->rbp + 8) : 0;
    this->stage = this->stage == 0 &&
        ((this->parent & 7) != 0 || this->parent < this->base + 0x78 ||
         this->parent > this->top - 0x10 || this->parent <= this->rbp) ?
        6 : this->stage;
    this->stage = this->stage == 0 &&
        (this->parent - this->rbp != 0xc0 ||
         (this->return_pc != wait_slide + WAIT_UNSLID_SYNC_RETURN &&
          this->return_pc != wait_slide + WAIT_UNSLID_ASYNC_RETURN)) ?
        7 : this->stage;

    this->called = this->stage == 0 ? *(uint64_t *)(this->rbp - 0x30) : 0;
    this->requested = this->stage == 0 ? *(uint64_t *)(this->parent - 0x58) : 0;
    this->parent_called = this->stage == 0 ? *(uint64_t *)(this->parent - 0x48) : 0;
    this->mode = this->stage == 0 ? *(uint32_t *)(this->parent - 0x30) : 0;
    this->action = this->stage == 0 ? *(uint64_t *)(this->parent - 0x38) : 0;
    this->action_arg0 = this->stage == 0 ? *(uint64_t *)(this->parent - 0x60) : 0;
    this->action_arg1 = this->stage == 0 ? *(uint64_t *)(this->parent - 0x68) : 0;
    this->stage = this->stage == 0 &&
        !((this->mode == 0 && this->return_pc == wait_slide + WAIT_UNSLID_SYNC_RETURN) ||
          (this->mode == 1 && this->return_pc == wait_slide + WAIT_UNSLID_ASYNC_RETURN)) ?
        8 : this->stage;
    this->stage = this->stage == 0 &&
        (this->rbx != this->parent - 0x70 ||
         this->called != this->parent_called) ? 9 : this->stage;

    this->response_loaded = this->stage == 0;
    this->response_before = this->response_loaded ? *(uint64_t *)this->rbx : 0;
    this->response_after = this->response_loaded ? *(uint64_t *)this->rbx : 0;
    /* Requested may legitimately have upper bits, including CPUMASK_ALL. */
    this->stage = this->stage == 0 &&
        ((this->called & ~this->requested) != 0 ||
         (this->called & ~15ULL) != 0 ||
         (this->response_before & ~this->called) != 0 ||
         (this->response_after & ~this->called) != 0) ? 10 : this->stage;
    this->stage = this->stage == 0 &&
        (this->response_before & ~this->response_after) != 0 ? 11 : this->stage;
    this->ok = this->stage == 0;
    /* Clause timestamp labels this capture; it does not bracket the loads. */
    this->sample_timestamp_ns = timestamp;
    this->profile_generation = sequence[cpu];
    this->pid = (uint64_t)pid;
    this->tid = (uint64_t)tid;
    this->rflags = this->flags;
    this->slide = wait_slide;
    this->zero_bits = 0;
    WAIT_FIELD_LIST(WAIT_ZERO_FIELD, cpu)
    this->wait_next = (wait_sequence[cpu] & ~1ULL) + 2;
    wait_sequence[cpu] = this->ok ? this->wait_next - 1 : wait_sequence[cpu];
    WAIT_FIELD_LIST(WAIT_STORE_FIELD, cpu)
    wait_zero[cpu] = this->ok ? this->zero_bits + 1 : wait_zero[cpu];
    wait_sequence[cpu] = this->ok ? this->wait_next : wait_sequence[cpu];
    wait_invalid[cpu] = wait_invalid[cpu] + !this->ok;
}

dtrace:::ERROR
{
    /* An idempotent flag, separate from the profile-owned wait sequence. */
    wait_error[cpu] = 2;
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

#define WAIT_EXPORT_FIELD(c, name, index) \
    this->wr[2 + index] = wait_value[c, index];
#define WAIT_EXPORT(c) \
syscall::write*:entry \
/pid == $1 && arg0 == $3 && arg1 == $2 && arg2 == 0/ \
{ \
    this->wr = (uint64_t *)alloca(WAIT_SLOT_BYTES); \
    this->wr[0] = wait_sequence[c]; \
    this->wr[1] = wait_zero[c] - 1; \
    WAIT_FIELD_LIST(WAIT_EXPORT_FIELD, c) \
    this->wr[2 + WAIT_FIELD_COUNT] = wait_zero[c] != 0 ? wait_sequence[c] : 0; \
    this->wr[3 + WAIT_FIELD_COUNT] = wait_invalid[c] - 1; \
    this->wr[4 + WAIT_FIELD_COUNT] = wait_error[c] - 1; \
    this->wr[5 + WAIT_FIELD_COUNT] = c; \
    copyout(this->wr, (uintptr_t)$2 + WAIT_PAGE_OFFSET + c * WAIT_SLOT_BYTES, \
        WAIT_SLOT_BYTES); \
}

WAIT_EXPORT(0)
WAIT_EXPORT(1)
WAIT_EXPORT(2)
WAIT_EXPORT(3)

syscall::write*:entry
/pid == $1 && arg0 == $3 && arg1 == $2 && arg2 == 0/
{
    this->h = (uint64_t *)alloca(32);
    this->h[1] = timestamp;
    this->h[2] = out_of_range_cpu;
    this->h[3] = 0;
    copyout(this->h + 1, (uintptr_t)$2 + 8, 24);
    this->h[0] = WAIT_MAGIC;
    copyout(this->h, (uintptr_t)$2, 8);
}
