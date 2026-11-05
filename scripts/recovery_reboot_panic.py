"""Own one fixed reboot_np helper under a durable external acknowledgement."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import selectors
import subprocess
import time

import recovery_panic_control as utility
import recovery_nvram_panic as classifier

PROTOCOL = 'vz-reboot-panic-v1'
KIND = 'reboot-panic-v1'
FLAGS = 3072
LIMIT = 65536
HEX = re.compile(r'[0-9a-f]{64}\Z')
RECEIPT_KEYS = {'protocol', 'control_kind', 'flags', 'source_hashes', 'context_sha256',
                'helper_source_sha256', 'helper_sha256', 'nonce_sha256', 'signature',
                'preflight_status', 'permission_verified'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def validate_context(context):
    expected = {'actions':'true', 'repo':'Code-Hex/vz-ci-test', 'ref':'refs/heads/main',
                'event':'workflow_dispatch', 'runner_environment':'github-hosted', 'trigger':'reboot-quick',
                'debug_source':'bootplist', 'after_debug_boot':'panic-nonce-syscall'}
    if (type(context) is not dict or any(context.get(k) != v for k,v in expected.items()) or
            context.get('debug_boot') is not True or
            any(type(context.get(k)) is not str or not re.fullmatch(pattern, context[k]) for k,pattern in
                (('run_id',r'[1-9][0-9]{0,19}'), ('attempt',r'[1-9][0-9]{0,4}'), ('sha',r'[0-9a-f]{40}')))):
        raise ValueError('context_invalid')


def validate_nonce(nonce):
    if type(nonce) is not str or not HEX.fullmatch(nonce): raise ValueError('nonce_invalid')


def child_env(context, nonce, boot_uuid):
    validate_context(context); validate_nonce(nonce)
    if type(boot_uuid) is not str or not utility.UUID.fullmatch(boot_uuid): raise ValueError('boot_invalid')
    names = {'actions':'GITHUB_ACTIONS','repo':'GITHUB_REPOSITORY','ref':'GITHUB_REF','event':'GITHUB_EVENT_NAME',
             'runner_environment':'RUNNER_ENVIRONMENT','run_id':'GITHUB_RUN_ID','attempt':'GITHUB_RUN_ATTEMPT',
             'sha':'GITHUB_SHA','trigger':'RECOVERY_TRIGGER','debug_source':'RECOVERY_DEBUG_SOURCE',
             'after_debug_boot':'RECOVERY_AFTER_DEBUG_BOOT'}
    return {**utility.CHILD_ENV, **{v:context[k] for k,v in names.items()}, 'RECOVERY_DEBUG_BOOT':'true',
            'VZ_RECOVERY_NONCE':nonce, 'VZ_RECOVERY_BOOT_UUID':boot_uuid.upper()}


def source_hashes():
    return {'control_sha256':digest(Path(__file__).read_bytes()),
            'utilities_sha256':digest(Path(utility.__file__).read_bytes()),
            'classifier_sha256':digest(Path(classifier.__file__).read_bytes())}


def record(directory, name, value, save, sync):
    save(Path(directory)/name, canonical(value)); sync(Path(directory))


def _receipt(directory, nonce, context, preflight):
    return {'protocol':PROTOCOL, 'control_kind':KIND, 'flags':FLAGS, 'source_hashes':source_hashes(),
            'context_sha256':digest(canonical(context)),
            'helper_source_sha256':digest(utility.read_private(directory/'helper.c',0o600,65536)),
            'helper_sha256':digest(utility.read_private(directory/'helper',0o700,16*1024*1024)),
            'nonce_sha256':digest(nonce.encode()), 'signature':'verified',
            'preflight_status':preflight, 'permission_verified':False}


def _command(argv, directory, label, deadline):
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=utility.CHILD_ENV)
    try:
        out, err, overflow, faults = _drain(child, deadline=deadline)
        utility.once_record(directory,label+'.json',{'exit':child.returncode, 'output_overflow':overflow, 'ownership_faults':faults},lambda _:None)
        if child.returncode != 0 or overflow or faults: raise ValueError('command_failed')
        return out,err
    finally:
        _cleanup(child)


def build(directory, nonce, save, sync, *, context, source_path):
    validate_context(context); validate_nonce(nonce)
    private=Path(directory)/'panic-control'; private.mkdir(mode=0o700); sync(Path(directory))
    source=Path(source_path).read_bytes()
    if Path(source_path).name != 'reboot_panic.c' or not source or len(source)>65536: raise ValueError('source_invalid')
    save(private/'helper.c',source); sync(private)
    binary=private/'helper'
    _command(['/usr/bin/xcrun','clang','-arch','x86_64','-O0','-Wall','-Wextra','-Werror',str(private/'helper.c'),'-o',str(binary)],private,'build',time.monotonic()+30)
    _command(['/usr/bin/codesign','-s','-','-f',str(binary)],private,'sign',time.monotonic()+15)
    _command(['/usr/bin/codesign','--verify','--strict',str(binary)],private,'signature',time.monotonic()+15)
    os.chmod(binary,0o700)
    with binary.open('rb') as stream: os.fsync(stream.fileno())
    sync(private)
    built=_receipt(private,nonce,context,'not_run'); record(private,'built.json',built,save,sync)
    return built


def validate_built(directory, nonce, built, *, context):
    validate_context(context); validate_nonce(nonce); private=Path(directory)/'panic-control'
    expected=_receipt(private,nonce,context,'not_run')
    if (type(built) is not dict or set(built)!=RECEIPT_KEYS or type(built['flags']) is not int or
            built['permission_verified'] is not False or built!=expected or
            json.loads(utility.read_private(private/'built.json',0o600,65536))!=built): raise ValueError('built_invalid')
    return private/'helper'


def validate_prepared(directory, nonce, prepared, *, context):
    private=Path(directory)/'panic-control'
    built=json.loads(utility.read_private(private/'built.json',0o600,65536))
    binary=validate_built(directory,nonce,built,context=context)
    expected={**built,'preflight_status':'passed'}
    if (type(prepared) is not dict or set(prepared)!=RECEIPT_KEYS or type(prepared['flags']) is not int or
            prepared['permission_verified'] is not False or prepared!=expected or
            json.loads(utility.read_private(private/'prepared.json',0o600,65536))!=prepared): raise ValueError('prepared_invalid')
    return binary


def _deadline(deadline, seconds=20):
    if type(deadline) not in (int,float) or not math.isfinite(deadline): raise ValueError('deadline_invalid')
    end=min(deadline-2,time.monotonic()+seconds)
    if end<=time.monotonic(): raise TimeoutError('startup_budget')
    return end


def ready_line(nonce, pid):
    return ('REBOOT_READY '+str(pid)+' '+classifier.syscall_marker(nonce,pid)+'\n').encode()


def _read_ready(child, nonce, deadline):
    expected=ready_line(nonce,child.pid); data=bytearray(); selector=selectors.DefaultSelector()
    selector.register(child.stdout,selectors.EVENT_READ)
    try:
        while bytes(data)!=expected:
            left=deadline-time.monotonic()
            if left<=0 or not selector.select(left): raise TimeoutError('ready_timeout')
            part=os.read(child.stdout.fileno(),len(expected)+1-len(data))
            if not part: raise ValueError('ready_eof')
            data.extend(part)
            if not expected.startswith(data): raise ValueError('ready_invalid')
        if child.poll() is not None: raise ValueError('ready_exited')
    finally: selector.close()
    return bytes(data)


def _cleanup(child):
    if child.poll() is None: child.kill()
    child.wait(timeout=2)
    for stream in (child.stdin,child.stdout,child.stderr):
        if stream is not None: stream.close()


def _drain(child, *, deadline=None, initial_bytes=0, read_fn=os.read, select_fn=select.select,
           set_blocking_fn=os.set_blocking, sleep_fn=time.sleep):
    streams=[child.stdout,child.stderr]; data=[bytearray(),bytearray()]; overflow=False; faults=0
    nonblocking=set()
    for stream in streams:
        try:
            set_blocking_fn(stream.fileno(),False); nonblocking.add(stream)
        except BaseException:
            if deadline is not None: raise
            faults+=1
    while streams:
        try:
            if deadline is not None and time.monotonic()>=deadline: raise TimeoutError('child_timeout')
            fallback=False
            try:
                readable,_,_=select_fn(streams,[],[],min(0.1,max(0,deadline-time.monotonic())) if deadline is not None else 0.1)
            except BaseException:
                if deadline is not None: raise
                faults+=1; readable=list(streams); fallback=True
                try: sleep_fn(0.05)
                except BaseException: faults+=1
            for stream in readable:
                if fallback and stream not in nonblocking and child.poll() is None:
                    continue
                try: part=read_fn(stream.fileno(),4096)
                except BlockingIOError: continue
                except BaseException:
                    if deadline is not None: raise
                    faults+=1
                    if child.poll() is not None: streams.remove(stream)
                    continue
                if not part: streams.remove(stream); continue
                index=0 if stream is child.stdout else 1
                room=max(0,LIMIT-initial_bytes-sum(map(len,data)))
                data[index].extend(part[:room]); overflow=overflow or len(part)>room
        except BaseException:
            if deadline is not None: raise
            faults+=1
            try: sleep_fn(0.05)
            except BaseException: faults+=1
    while True:
        try:
            child.wait(timeout=max(0.01,deadline-time.monotonic()) if deadline is not None else None); break
        except BaseException:
            if deadline is not None: raise
            faults+=1
    return bytes(data[0]),bytes(data[1]),overflow,faults


def _preflight(binary, nonce, env, deadline):
    child=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    try:
        _read_ready(child,nonce,deadline)
        if os.write(child.stdin.fileno(),b'Q')!=1: raise ValueError('preflight_write')
        out,err,overflow,faults=_drain(child,deadline=deadline)
        if child.returncode!=0 or out or err or overflow or faults: raise ValueError('preflight_failed')
    finally: _cleanup(child)


def prepare(directory, nonce, save, sync, *, context, deadline):
    private=Path(directory)/'panic-control'; end=_deadline(deadline)
    try:
        built=json.loads(utility.read_private(private/'built.json',0o600,65536))
        binary=validate_built(directory,nonce,built,context=context)
        raw,_=_command(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],private,'prepare-boot',end)
        boot=raw.decode('ascii').removesuffix('\n')
        _preflight(binary,nonce,child_env(context,nonce,boot),end)
        prepared={**built,'preflight_status':'passed'}; record(private,'prepared.json',prepared,save,sync)
        return prepared
    except BaseException:
        record(private,'prepare-failure.json',{'status':'failed','permission_verified':False},save,sync)
        raise


def parse_returned(raw):
    match=re.fullmatch(rb'REBOOT_RETURNED (-1|0) ([0-9]{1,10})\n',raw)
    if not match or int(match[2])>2147483647: raise ValueError('return_invalid')
    return int(match[1]),int(match[2])


def _fire_owned(binary, directory, scope, helper_sha256, env, save, sync, on_ready, current_boot_uuid, deadline, *, drain=_drain):
    private=Path(directory)/'panic-control'; end=_deadline(deadline)
    utility.once_record(private,'intent.json',{'scope':scope,'prepared':json.loads(utility.read_private(private/'prepared.json',0o600,65536))},sync)
    child=None; attempted=False; released='not_released'
    try:
        child=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        initial=_read_ready(child,scope['nonce'],end)
        trigger={'scope':scope,'helper_sha256':helper_sha256,'helper_pid':child.pid,'ready':True}
        if (on_ready(trigger) is not True or time.monotonic()>=end or child.poll() is not None or
                current_boot_uuid().upper()!=scope['debug_boot_uuid'].upper() or time.monotonic()>=end):
            return {'phase':'not_released','release_status':'not_released','helper_exit':None,'result':None,'errno':None,
                    'output_complete':False,'output_overflow':False,'ownership_faults':0}
        utility.once_record(private,'release-attempt.json',trigger,sync)
        attempted=True
        try:
            released='released' if os.write(child.stdin.fileno(),b'G')==1 else 'unknown'
        except BaseException: released='unknown'
        out,err,overflow,faults=drain(child,initial_bytes=len(initial))
        record(private,'helper.stdout.json',{'sha256':digest(initial+out),'bytes':len(initial)+len(out)},save,sync)
        save(private/'helper.stdout',(initial+out)[:LIMIT]); save(private/'helper.stderr',err); sync(private)
        result=error=None
        try: result,error=parse_returned(out)
        except ValueError: pass
        phase='returned' if released=='released' and child.returncode==70 and result is not None and not err and not overflow and not faults else 'unknown'
        return {'phase':phase,'release_status':released,'helper_exit':child.returncode,'result':result,'errno':error,
                'output_complete':not (faults or overflow),'output_overflow':overflow,'ownership_faults':faults}
    finally:
        if child is not None:
            if not attempted: _cleanup(child)
            elif child.poll() is not None:
                for stream in (child.stdin,child.stdout,child.stderr): stream.close()


def fire(directory, scope, prepared, save, sync, on_ready, current_boot_uuid, *, context, deadline):
    validate_context(context); utility.validate_scope(scope)
    if scope['binding']!=context['run_id']+'/'+context['attempt']+'/'+context['sha']: raise ValueError('scope_context_mismatch')
    binary=validate_prepared(directory,scope['nonce'],prepared,context=context)
    if current_boot_uuid().upper()!=scope['debug_boot_uuid'].upper(): raise ValueError('boot_mismatch')
    return _fire_owned(binary,directory,scope,prepared['helper_sha256'],child_env(context,scope['nonce'],scope['debug_boot_uuid']),
                       save,sync,on_ready,current_boot_uuid,deadline)
