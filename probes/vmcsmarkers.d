/* kind 16..20: RIP/RSP, RFLAGS/activity, reason/pin, CPU/timer, exit-controls/IRQ-info.
 * kind 21: return offset/value completes the batch. Kind 31 is fault/illval, or UINT64_MAX/next on capacity exhaustion. */
#pragma D option quiet
#pragma D option bufpolicy=fill
#pragma D option bufsize=1m

uint64_t owner_tid;
uint64_t bad;

dtrace:::BEGIN
{
    printf("{\"type\":\"armed\",\"protocol\":\"vmcsmarkers-v1\"}\n");
}

syscall::write*:entry
/pid == $1 && arg0 == 1 && arg2 == 0 && owner_tid == 0 && !bad/
{
    owner_tid = tid;
    self->in_publish = 1;
    self->error_publishing = 0;
    self->error_slot = 0;
    this->r = (uint64_t *)alloca(56);
    this->r[0] = timestamp;
    this->r[1] = caller;
    this->r[2] = 0;
    this->r[3] = 0;
    this->r[4] = tid;
    this->r[5] = ((uint64_t)cpu << 32) | 2;
    copyout(this->r, (uintptr_t)$2, 48);
    this->r[6] = 1;
    copyout(this->r + 6, (uintptr_t)$2 + 48, 8);
    self->next = (uint64_t)1;
    self->in_publish = 0;
}

fbt:com.apple.driver.AppleHV:_ZN13hv_vmx_vcpu_t26THREAD_TRAP_vcpu_run_untilEPS_y:entry
/pid == $1 && tid == owner_tid && !bad && self->next != 0/
{
    self->active = 1;
}

fbt:com.apple.driver.AppleHV:_ZN13hv_vmx_vcpu_t11enter_guestEPjS0_:return
/pid == $1 && tid == owner_tid && self->active && !bad && self->next > 26/
{
    bad = 1;
    self->in_publish = 1;
    self->error_slot = self->next;
    printf("{\"type\":\"capacity\",\"next\":%llu}\n", (uint64_t)self->next);
    this->r = (uint64_t *)alloca(56);
    this->r[0] = timestamp;
    this->r[1] = caller;
    this->r[2] = (uint64_t)-1;
    this->r[3] = self->next;
    this->r[4] = tid;
    this->r[5] = ((uint64_t)cpu << 32) | 63;
    copyout(this->r, (uintptr_t)$2 + self->error_slot * 56, 48);
    this->r[6] = self->error_slot + 1;
    copyout(this->r + 6, (uintptr_t)$2 + self->error_slot * 56 + 48, 8);
    self->in_publish = 0;
}

fbt:com.apple.driver.AppleHV:_ZN13hv_vmx_vcpu_t11enter_guestEPjS0_:return
/pid == $1 && tid == owner_tid && self->active && !bad &&
    self->next != 0 && self->next <= 26/
{
    self->in_publish = 1;
    self->error_slot = self->next;
    this->offset = arg0;
    this->result = arg1;
    this->sample_time = timestamp;
    this->sample_caller = caller;
    this->sample_cpu = cpu;
    this->rip = vmregs[0x681e];
    this->rsp = vmregs[0x681c];
    this->rflags = vmregs[0x6820];
    this->activity = vmregs[0x4826];
    this->reason = vmregs[0x4402];
    this->pin = vmregs[0x4000];
    this->primary = vmregs[0x4002];
    this->timer = vmregs[0x482e];
    this->exit_controls = vmregs[0x400c];
    this->irq_info = vmregs[0x4404];
    this->base = self->next;
    this->r = (uint64_t *)alloca(56);
    this->r[0] = this->sample_time;
    this->r[1] = this->sample_caller;
    this->r[4] = tid;
    this->r[2] = this->rip;
    this->r[3] = this->rsp;
    this->r[5] = ((uint64_t)this->sample_cpu << 32) | 33;
    copyout(this->r, (uintptr_t)$2 + (this->base + 0) * 56, 48);
    this->r[6] = this->base + 1;
    copyout(this->r + 6, (uintptr_t)$2 + (this->base + 0) * 56 + 48, 8);
    self->error_slot = this->base + 1;
    this->r[2] = this->rflags;
    this->r[3] = this->activity;
    this->r[5] = ((uint64_t)this->sample_cpu << 32) | 35;
    copyout(this->r, (uintptr_t)$2 + (this->base + 1) * 56, 48);
    this->r[6] = this->base + 2;
    copyout(this->r + 6, (uintptr_t)$2 + (this->base + 1) * 56 + 48, 8);
    self->error_slot = this->base + 2;
    this->r[2] = this->reason;
    this->r[3] = this->pin;
    this->r[5] = ((uint64_t)this->sample_cpu << 32) | 37;
    copyout(this->r, (uintptr_t)$2 + (this->base + 2) * 56, 48);
    this->r[6] = this->base + 3;
    copyout(this->r + 6, (uintptr_t)$2 + (this->base + 2) * 56 + 48, 8);
    self->error_slot = this->base + 3;
    this->r[2] = this->primary;
    this->r[3] = this->timer;
    this->r[5] = ((uint64_t)this->sample_cpu << 32) | 39;
    copyout(this->r, (uintptr_t)$2 + (this->base + 3) * 56, 48);
    this->r[6] = this->base + 4;
    copyout(this->r + 6, (uintptr_t)$2 + (this->base + 3) * 56 + 48, 8);
    self->error_slot = this->base + 4;
    this->r[2] = this->exit_controls;
    this->r[3] = this->irq_info;
    this->r[5] = ((uint64_t)this->sample_cpu << 32) | 41;
    copyout(this->r, (uintptr_t)$2 + (this->base + 4) * 56, 48);
    this->r[6] = this->base + 5;
    copyout(this->r + 6, (uintptr_t)$2 + (this->base + 4) * 56 + 48, 8);
    self->error_slot = this->base + 5;
    this->r[2] = this->offset;
    this->r[3] = this->result;
    this->r[5] = ((uint64_t)this->sample_cpu << 32) | 43;
    copyout(this->r, (uintptr_t)$2 + (this->base + 5) * 56, 48);
    this->r[6] = this->base + 6;
    copyout(this->r + 6, (uintptr_t)$2 + (this->base + 5) * 56 + 48, 8);
    self->error_slot = this->base + 6;
    self->next = this->base + 6;
    self->in_publish = 0;
}

fbt:com.apple.driver.AppleHV:_ZN13hv_vmx_vcpu_t26THREAD_TRAP_vcpu_run_untilEPS_y:return
/pid == $1 && tid == owner_tid/
{
    self->active = 0;
}

dtrace:::ERROR
{
    bad = 1;
    printf("{\"type\":\"error\",\"probe\":%llu,\"action\":%llu,\"offset\":%llu,\"fault\":%llu,\"illval\":%llu}\n",
        (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4, (uint64_t)arg5);
}

dtrace:::ERROR
/pid == $1 && tid == owner_tid && self->in_publish &&
    !self->error_publishing && self->error_slot < 32/
{
    self->error_publishing = 1;
    this->r = (uint64_t *)alloca(56);
    this->r[0] = timestamp;
    this->r[1] = caller;
    this->r[2] = arg4;
    this->r[3] = arg5;
    this->r[4] = tid;
    this->r[5] = ((uint64_t)cpu << 32) | 63;
    copyout(this->r, (uintptr_t)$2 + self->error_slot * 56, 48);
    this->r[6] = self->error_slot + 1;
    copyout(this->r + 6, (uintptr_t)$2 + self->error_slot * 56 + 48, 8);
    self->in_publish = 0;
}

tick-12s
{
    exit(0);
}

dtrace:::END
{
    printf("{\"type\":\"finished\",\"bad\":%llu}\n", bad);
}
