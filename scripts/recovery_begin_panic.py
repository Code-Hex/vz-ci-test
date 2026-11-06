"""Prepare one fixed BEGIN program and own its single launch after acknowledgement."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import recovery_bootargs as boot
import recovery_panic_control as utility
import recovery_reboot_panic as drain_owner

PROTOCOL='vz-begin-panic-v1'
KIND='dtrace-begin-v1'
DTRACE='/usr/sbin/dtrace'
LIMIT=65536
BUILT_KEYS={'protocol','control_kind','source_hashes','context_sha256','nonce_sha256','program_sha256',
            'dtrace_sha256','permission_verified','build_status'}
PREPARED_KEYS=BUILT_KEYS|{'compile_status','debug_boot_uuid','destructive_policy'}


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def _hex(value): return type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value) is not None


def validate_context(context):
    expected={'actions':'true','repo':'Code-Hex/vz-ci-test','ref':'refs/heads/main','event':'workflow_dispatch',
              'runner_environment':'github-hosted','trigger':'reboot-quick','debug_source':'bootplist','after_debug_boot':'panic-nonce-begin'}
    if (type(context) is not dict or any(context.get(k)!=v for k,v in expected.items()) or context.get('debug_boot') is not True or
            any(type(context.get(k)) is not str or not re.fullmatch(pattern,context[k]) for k,pattern in
                (('run_id',r'[1-9][0-9]{0,19}'),('attempt',r'[1-9][0-9]{0,4}'),('sha',r'[0-9a-f]{40}')))):
        raise ValueError('begin_context_invalid')


def program(nonce):
    if not _hex(nonce): raise ValueError('begin_nonce_invalid')
    return ('dtrace:::ERROR { printf("VZ_BEGIN_FAULT '+nonce+' %u\\n", (uint32_t)arg4); exit(71); }\n'
            'dtrace:::BEGIN { panic(); printf("VZ_BEGIN_AFTER_PANIC '+nonce+'\\n"); exit(70); }\n').encode('ascii')


def source_hashes():
    return {'begin_sha256':sha(Path(__file__).read_bytes()),'drain_sha256':sha(Path(drain_owner.__file__).read_bytes()),
            'utilities_sha256':sha(Path(utility.__file__).read_bytes()),'getter_sha256':sha(Path(boot.__file__).read_bytes())}


def _tool_sha():
    fd=os.open(DTRACE,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=16*1024*1024: raise ValueError('dtrace_binary_invalid')
        raw=stream.read(16*1024*1024+1);after=os.fstat(stream.fileno())
    if len(raw)!=before.st_size or (before.st_ino,before.st_mtime_ns,before.st_size)!=(after.st_ino,after.st_mtime_ns,after.st_size):
        raise ValueError('dtrace_binary_changed')
    return sha(raw)


def _record(directory,name,value,save,sync):
    save(Path(directory)/name,canonical(value));sync(Path(directory))


def _checked_built(value,nonce,context):
    validate_context(context);raw=program(nonce)
    if (type(value) is not dict or set(value)!=BUILT_KEYS or value['protocol']!=PROTOCOL or value['control_kind']!=KIND or
            value['source_hashes']!=source_hashes() or value['context_sha256']!=sha(canonical(context)) or
            value['nonce_sha256']!=sha(nonce.encode()) or value['program_sha256']!=sha(raw) or not _hex(value['dtrace_sha256']) or
            value['permission_verified'] is not False or value['build_status']!='written'):
        raise ValueError('begin_build_invalid')
    return copy.deepcopy(value)


def checked_prepared(value,nonce,*,context):
    if type(value) is not dict or set(value)!=PREPARED_KEYS: raise ValueError('begin_prepared_invalid')
    _checked_built({k:value[k] for k in BUILT_KEYS},nonce,context)
    policy=value['destructive_policy']
    if (value['compile_status']!='passed' or type(value['debug_boot_uuid']) is not str or not utility.UUID.fullmatch(value['debug_boot_uuid']) or
            type(policy) is not dict or set(policy)!={'status','value'} or policy['status']!='observed' or
            type(policy['value']) is not int or policy['value']!=0): raise ValueError('begin_prepared_invalid')
    return copy.deepcopy(value)


def build(directory,nonce,save,sync,*,context):
    validate_context(context);raw=program(nonce);tool_sha=_tool_sha()
    private=Path(directory)/'panic-control';private.mkdir(mode=0o700);sync(Path(directory))
    save(private/'program.d',raw);sync(private)
    built={'protocol':PROTOCOL,'control_kind':KIND,'source_hashes':source_hashes(),'context_sha256':sha(canonical(context)),
           'nonce_sha256':sha(nonce.encode()),'program_sha256':sha(raw),'dtrace_sha256':tool_sha,
           'permission_verified':False,'build_status':'written'}
    _record(private,'built.json',built,save,sync);return built


def validate_prepared(directory,nonce,prepared,*,context):
    value=checked_prepared(prepared,nonce,context=context);private=Path(directory)/'panic-control'
    if (json.loads(utility.read_private(private/'prepared.json',0o600,LIMIT))!=value or
            json.loads(utility.read_private(private/'built.json',0o600,LIMIT))!={k:value[k] for k in BUILT_KEYS} or
            utility.read_private(private/'program.d',0o600,LIMIT)!=program(nonce) or _tool_sha()!=value['dtrace_sha256']):
        raise ValueError('begin_private_binding_invalid')
    return Path(DTRACE)


def _operation_deadline(deadline):
    if type(deadline) not in (int,float) or not math.isfinite(deadline): raise ValueError('begin_deadline_invalid')
    end=min(deadline-2,time.monotonic()+30)
    if end<=time.monotonic(): raise TimeoutError('begin_budget_unavailable')
    return end


def _stop_preflight(child):
    try:
        if child.poll() is None: child.kill()
        child.wait(timeout=2)
    finally:
        for stream in (child.stdin,child.stdout,child.stderr):
            if stream is not None:stream.close()


def _command(argv,directory,label,deadline):
    if time.monotonic()>=deadline:raise TimeoutError('begin_budget_unavailable')
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=utility.CHILD_ENV)
    try:
        out,err,overflow,faults=drain_owner._drain(child,deadline=deadline)
        utility.once_record(directory,label+'.json',{'exit':child.returncode,'output_overflow':overflow,'ownership_faults':faults},lambda _:None)
        for name,data in ((label+'.stdout',out),(label+'.stderr',err)):
            fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        if overflow or faults:raise ValueError('begin_command_capture_invalid')
        return child.returncode,out,err
    finally:_stop_preflight(child)


def _boot_uuid(run,private,label,end):
    code,raw,_=run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],private,label,min(end,time.monotonic()+8))
    if code!=0 or not re.fullmatch(rb'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\n',raw):
        raise ValueError('begin_boot_uuid_invalid')
    return raw[:-1].decode().upper()


def prepare(directory,nonce,save,sync,*,context,deadline,run_command=None,read=None):
    private=Path(directory)/'panic-control';end=_operation_deadline(deadline);run=_command if run_command is None else run_command
    policy={'status':'unavailable'}
    try:
        built=_checked_built(json.loads(utility.read_private(private/'built.json',0o600,LIMIT)),nonce,context)
        if utility.read_private(private/'program.d',0o600,LIMIT)!=program(nonce) or _tool_sha()!=built['dtrace_sha256']:
            raise ValueError('begin_private_binding_invalid')
        current=_boot_uuid(run,private,'prepare-boot',end)
        if end-time.monotonic()<7:raise TimeoutError('begin_policy_budget_unavailable')
        policy=boot.kernel_field_state('dtrace_destructive_disallow',read=read,timeout=5)
        if type(policy) is not dict or set(policy)!={'status','value'} or policy['status']!='observed' or type(policy['value']) is not int or policy['value']!=0:
            raise ValueError('begin_policy_not_observed_zero')
        code,_,_=run([DTRACE,'-w','-e','-q','-n',program(nonce).decode('ascii')],private,'begin-compile',min(end,time.monotonic()+20))
        if code!=0:raise ValueError('begin_compile_failed')
        if _boot_uuid(run,private,'prepared-boot',end)!=current:raise ValueError('begin_boot_changed')
        prepared={**built,'compile_status':'passed','debug_boot_uuid':current,'destructive_policy':policy}
        checked_prepared(prepared,nonce,context=context)
        _record(private,'prepared.json',prepared,save,sync);return prepared
    except BaseException:
        _record(private,'prepare-failure.json',{'status':'failed','destructive_policy':policy,'permission_verified':False},save,sync)
        raise


def parse_returned(raw,code,nonce):
    program(nonce)
    if raw==('VZ_BEGIN_AFTER_PANIC '+nonce+'\n\n').encode() and type(code) is int and code==70:return 'after_action',None
    match=re.fullmatch(rb'VZ_BEGIN_FAULT '+nonce.encode()+rb' (0|[1-9][0-9]{0,9})\n\n',raw)
    if match and int(match[1])<=0xffffffff and type(code) is int and code==71:return 'fault',int(match[1])
    raise ValueError('begin_return_unrecognized')


def fire(directory,scope,prepared,save,sync,on_ready,current_boot_uuid,*,context,deadline,start_child=None,drain=None):
    validate_context(context);utility.validate_scope(scope)
    if type(deadline) not in (int,float) or not math.isfinite(deadline):raise ValueError('begin_deadline_invalid')
    if deadline<=time.monotonic():raise TimeoutError('begin_budget_unavailable')
    end=deadline
    validate_prepared(directory,scope['nonce'],prepared,context=context)
    if (scope['binding']!=context['run_id']+'/'+context['attempt']+'/'+context['sha'] or
            prepared['debug_boot_uuid'].upper()!=scope['debug_boot_uuid'].upper() or current_boot_uuid().upper()!=scope['debug_boot_uuid'].upper()):
        raise ValueError('begin_scope_mismatch')
    private=Path(directory)/'panic-control'
    utility.once_record(private,'intent.json',{'scope':scope,'prepared':prepared},sync)
    trigger={'scope':scope,'program_sha256':prepared['program_sha256'],'dtrace_sha256':prepared['dtrace_sha256'],'prepared':True}
    result={'phase':'not_launched','launch_status':'not_launched','dtrace_exit':None,'outcome':None,'fault_code':None,
            'output_complete':False,'output_overflow':False,'ownership_faults':0}
    if on_ready(copy.deepcopy(trigger)) is not True or time.monotonic()>=end or current_boot_uuid().upper()!=scope['debug_boot_uuid'].upper() or time.monotonic()>=end:return result
    utility.once_record(private,'launch-attempt.json',trigger,sync)
    if time.monotonic()>=end:return result
    start=subprocess.Popen if start_child is None else start_child;reader=drain_owner._drain if drain is None else drain
    try:child=start([DTRACE,'-w','-q','-n',program(scope['nonce']).decode('ascii')],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=utility.CHILD_ENV)
    except BaseException:return {**result,'phase':'unknown','launch_status':'unknown'}
    faults=0
    while True:
        try:out,err,overflow,drain_faults=reader(child);break
        except BaseException:faults+=1
    faults+=drain_faults
    for stream in (child.stdout,child.stderr):stream.close()
    save(private/'dtrace.stdout',out);save(private/'dtrace.stderr',err);sync(private)
    outcome,fault_code='unrecognized',None
    try:outcome,fault_code=parse_returned(out,child.returncode,scope['nonce'])
    except ValueError:pass
    _record(private,'returned.json',{'stdout_bytes':len(out),'stdout_sha256':sha(out),'stderr_bytes':len(err),'stderr_sha256':sha(err)},save,sync)
    return {'phase':'returned' if outcome!='unrecognized' and not overflow and not faults else 'unknown','launch_status':'launched',
            'dtrace_exit':child.returncode,'outcome':outcome,'fault_code':fault_code,'output_complete':not(overflow or faults),
            'output_overflow':overflow,'ownership_faults':faults}
