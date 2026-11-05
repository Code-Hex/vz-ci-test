"""Actions-only normal-boot kernel field snapshot."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

import recovery_bootargs as boot

KERNEL_UUID='87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
FIELD_NAMES=('debug_boot_arg','kdp_flag','send_registered','receive_registered','panicDebugging',
             'dtrace_destructive_disallow','coprocessor_paniclog_flush','commit_paniclog_to_nvram')
REASONS=('invalid_context','guard_failed','source_invalid','kernel_mismatch','io_error','deadline','interrupted','invalid_report')


class GateFailure(Exception):
    def __init__(self,reason):
        super().__init__('kernel_state_failed')
        self.reason=reason if reason in REASONS else 'invalid_report'


def require(condition,reason='invalid_report'):
    if not condition: raise GateFailure(reason)


def hexadecimal(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def validate_context(value):
    require(type(value) is dict and set(value)=={'run','attempt','sha','repository','ref','event','runner_environment'},'invalid_context')
    require(type(value['run']) is str and re.fullmatch('[1-9][0-9]{0,19}',value['run']) and
            type(value['attempt']) is str and re.fullmatch('[1-9][0-9]{0,4}',value['attempt']) and
            type(value['sha']) is str and re.fullmatch('[0-9a-f]{40}',value['sha']) and
            value['repository']=='Code-Hex/vz-ci-test' and value['ref']=='refs/heads/main' and
            value['event']=='workflow_dispatch' and value['runner_environment']=='github-hosted','invalid_context')


def checked_context(env):
    require(env.get('GITHUB_ACTIONS')=='true','invalid_context')
    value={key:env.get(name) for key,name in (('run','GITHUB_RUN_ID'),('attempt','GITHUB_RUN_ATTEMPT'),
        ('sha','GITHUB_SHA'),('repository','GITHUB_REPOSITORY'),('ref','GITHUB_REF'),
        ('event','GITHUB_EVENT_NAME'),('runner_environment','RUNNER_ENVIRONMENT'))}
    validate_context(value)
    return value


def source_hashes(script_path,bootargs_path,registry_path):
    script_path=Path(script_path).absolute()
    directory=script_path.parent.resolve()
    require(script_path.name=='kernel_state_readonly.py' and directory.name=='scripts','source_invalid')
    paths={'script':script_path,'workflow':directory.parent/'.github/workflows/kernel-state-readonly.yml',
           'bootargs':Path(bootargs_path),'registry':Path(registry_path)}
    expected={'script':directory/'kernel_state_readonly.py','workflow':directory.parent/'.github/workflows/kernel-state-readonly.yml',
              'bootargs':directory/'recovery_bootargs.py','registry':directory/'kdp_registry.py'}
    result={}
    for name,path in paths.items():
        require(not path.is_symlink() and path.is_file() and path.resolve()==expected[name],'source_invalid')
        result[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def read_kernel_identity(read=boot.capture):
    live=read(['/usr/sbin/sysctl','-n','kern.uuid'],4096,timeout=5)
    require(type(live) is bytes and re.fullmatch(KERNEL_UUID.encode()+rb'\n?',live,re.I),'kernel_mismatch')
    raw=read(['/usr/bin/xcrun','dwarfdump','--uuid','/System/Library/Kernels/kernel'],4096,timeout=20)
    pattern=rb'UUID: '+KERNEL_UUID.encode()+rb' \(x86_64\) /System/Library/Kernels/kernel\n?'
    require(type(raw) is bytes and re.fullmatch(pattern,raw,re.I),'kernel_mismatch')
    return {'live_uuid':KERNEL_UUID,'file_uuid':KERNEL_UUID}


def read_boot_profile(read=boot.capture):
    try:
        raw=read(['/usr/sbin/sysctl','-n','kern.bootargs'],65536,timeout=5)
        return boot.boot_argument_profile(raw[:-1] if raw.endswith(b'\n') else raw)
    except (OSError,subprocess.SubprocessError): return {'status':'unavailable'}
    except (ValueError,TypeError): return {'status':'invalid'}


def read_fields(*, read=None):
    readings=[]
    for attempt,budget in (('first',30),('repeat',5)):
        started=time.monotonic()
        result=boot.kernel_field_state('debug_boot_arg',read=read,timeout=budget)
        readings.append({'attempt':attempt,'budget_seconds':budget,
                         'elapsed_ms':int((time.monotonic()-started)*1000),'result':result})
    fields={'debug_boot_arg':readings[0]['result']}
    for name in FIELD_NAMES[1:]: fields[name]=boot.kernel_field_state(name,read=read)
    return fields,readings


def validate_field(name,field):
    require(type(field) is dict)
    if field.get('status')=='observed':
        require(set(field)=={'status','value'})
        boot.kernel_field_value(name,field['value'])
    else:
        require(set(field)=={'status','error'} and field['status'] in ('unavailable','invalid'))
        boot.kernel_error_summary(field['error'])


def validate_report(value):
    require(type(value) is dict and set(value)=={'protocol','scope','context','sources','kernel','boot_profile','fields','readings','completed'})
    require(value['protocol']=='kernel-field-readonly-v2' and value['scope']=='normal_boot_no_staging' and value['completed'] is True)
    validate_context(value['context'])
    require(type(value['sources']) is dict and set(value['sources'])=={'script','workflow','bootargs','registry'} and
            all(hexadecimal(item) for item in value['sources'].values()))
    require(type(value['kernel']) is dict and value['kernel']=={'live_uuid':KERNEL_UUID,'file_uuid':KERNEL_UUID})
    profile=value['boot_profile']
    require(type(profile) is dict)
    if profile.get('status')=='observed':
        require(set(profile)=={'status','debug_mask','nondebug_token_count','nondebug_sha256'} and
                (profile['debug_mask'] is None or type(profile['debug_mask']) is int and 0<=profile['debug_mask']<=0xffffffff) and
                type(profile['nondebug_token_count']) is int and 0<=profile['nondebug_token_count']<=1023 and
                hexadecimal(profile['nondebug_sha256']))
    else: require(set(profile)=={'status'} and profile['status'] in ('unavailable','invalid'))
    fields=value['fields']
    require(type(fields) is dict and set(fields)==set(FIELD_NAMES))
    for name,field in fields.items(): validate_field(name,field)
    readings=value['readings']
    require(type(readings) is list and len(readings)==2)
    for reading,(attempt,budget) in zip(readings,(('first',30),('repeat',5))):
        require(type(reading) is dict and set(reading)=={'attempt','budget_seconds','elapsed_ms','result'} and
                reading['attempt']==attempt and type(reading['budget_seconds']) is int and reading['budget_seconds']==budget and
                type(reading['elapsed_ms']) is int and 0<=reading['elapsed_ms']<=140000)
        validate_field('debug_boot_arg',reading['result'])
    require(fields['debug_boot_arg']==readings[0]['result'])
    return json.loads(json.dumps(value,sort_keys=True))


def deadline_signal(_number,_frame):
    signal.setitimer(signal.ITIMER_REAL,0)
    raise GateFailure('deadline')


def interrupted_signal(_number,_frame):
    signal.setitimer(signal.ITIMER_REAL,0)
    raise GateFailure('interrupted')


@contextmanager
def signal_guard():
    previous={number:signal.signal(number,handler) for number,handler in
              ((signal.SIGALRM,deadline_signal),(signal.SIGTERM,interrupted_signal),(signal.SIGINT,interrupted_signal))}
    signal.setitimer(signal.ITIMER_REAL,140)
    try: yield
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        for number,handler in previous.items(): signal.signal(number,handler)


def write_report(value,tempdir):
    value=validate_report(value)
    directory=Path(tempdir).resolve(strict=True)/'debug'
    directory.mkdir(mode=0o755,exist_ok=True)
    require(not directory.is_symlink(),'io_error')
    target=directory/'kernel-state-readonly.json'
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'w') as stream:
        os.fchmod(stream.fileno(),0o644)
        json.dump(value,stream,sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    return target


def main():
    try:
        with signal_guard():
            require(len(sys.argv)==1,'invalid_context')
            context=checked_context(os.environ)
            require(sys.platform=='darwin' and os.uname().machine=='x86_64' and os.geteuid()==0,'guard_failed')
            sources=source_hashes(__file__,boot.__file__,boot.kdp_registry.__file__)
            kernel=read_kernel_identity()
            profile=read_boot_profile()
            fields,readings=read_fields()
            value=validate_report({'protocol':'kernel-field-readonly-v2','scope':'normal_boot_no_staging',
                'context':context,'sources':sources,'kernel':kernel,'boot_profile':profile,'fields':fields,'readings':readings,'completed':True})
            write_report(value,os.environ['RUNNER_TEMP'])
            print(json.dumps(value,sort_keys=True),flush=True)
        return 0
    except GateFailure as error: reason=error.reason
    except (OSError,subprocess.SubprocessError): reason='io_error'
    except Exception: reason='invalid_report'
    print('kernel_state_failed '+reason,file=sys.stderr,flush=True)
    return 2


if __name__=='__main__': sys.exit(main())
