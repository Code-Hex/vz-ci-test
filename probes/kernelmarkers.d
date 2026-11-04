#pragma D option quiet
#pragma D option bufpolicy=fill
#pragma D option bufsize=1m

syscall::write*:entry
/pid == $1 && arg0 == 1 && arg2 == 0 && owner_tid == 0/
{
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
    self->next = 1;
    owner_tid = tid;
}

fbt:com.apple.driver.AppleHV:_ZN13hv_vmx_vcpu_t26THREAD_TRAP_vcpu_run_untilEPS_y:entry
/pid == $1 && tid == owner_tid/
{
    self->active = 1;
}

fbt:com.apple.driver.AppleHV:*THREAD_TRAP_vcpu_run_until*:entry,
fbt:com.apple.driver.AppleHV:*THREAD_TRAP_vcpu_run_until*:return,
fbt:com.apple.driver.AppleHV:*enter_guest*:entry,
fbt:com.apple.driver.AppleHV:*enter_guest*:return,
fbt:com.apple.driver.AppleHV:*handle_exit*:entry,
fbt:com.apple.driver.AppleHV:*handle_exit*:return,
fbt:com.apple.driver.AppleHV:*handle_hlt*:entry,
fbt:com.apple.driver.AppleHV:*handle_hlt*:return,
fbt:com.apple.driver.AppleHV:*halt_vcpu*:entry,
fbt:com.apple.driver.AppleHV:*halt_vcpu*:return,
fbt:com.apple.driver.AppleHV:*msleep_vcpu*:entry,
fbt:com.apple.driver.AppleHV:*msleep_vcpu*:return
/pid == $1 && tid == owner_tid && self->active && self->next < 32/
{
    this->kind = strstr(probefunc, "THREAD_TRAP_vcpu_run_until") != 0 ? 2 :
        strstr(probefunc, "enter_guest") != 0 ? 3 :
        strstr(probefunc, "handle_exit") != 0 ? 4 :
        strstr(probefunc, "handle_hlt") != 0 ? 5 :
        strstr(probefunc, "halt_vcpu") != 0 ? 6 : 7;
    this->n = self->next++;
    this->dst = (uintptr_t)$2 + this->n * 56;
    this->r = (uint64_t *)alloca(56);
    this->r[0] = timestamp;
    this->r[1] = caller;
    this->r[2] = arg0;
    this->r[3] = arg1;
    this->r[4] = tid;
    this->r[5] = ((uint64_t)cpu << 32) | (this->kind << 1) | (probename == "return");
    copyout(this->r, this->dst, 48);
    this->r[6] = this->n + 1;
    copyout(this->r + 6, this->dst + 48, 8);
}

fbt:com.apple.driver.AppleHV:_ZN13hv_vmx_vcpu_t26THREAD_TRAP_vcpu_run_untilEPS_y:return
/pid == $1 && tid == owner_tid/
{
    self->active = 0;
}

profile-97
/pid == $1 && tid == owner_tid && self->active && arg0 != 0 && self->next < 32/
{
    this->n = self->next++;
    this->dst = (uintptr_t)$2 + this->n * 56;
    this->r = (uint64_t *)alloca(56);
    this->r[0] = timestamp;
    this->r[1] = caller;
    this->r[2] = arg0;
    this->r[3] = arg1;
    this->r[4] = tid;
    this->r[5] = ((uint64_t)cpu << 32) | 16;
    copyout(this->r, this->dst, 48);
    this->r[6] = this->n + 1;
    copyout(this->r + 6, this->dst + 48, 8);
}

tick-12s
{
    exit(0);
}
