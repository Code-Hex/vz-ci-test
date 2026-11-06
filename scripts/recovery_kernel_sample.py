"""Collect bounded sample bytes after one owned kernel getter times out."""
import copy
import hashlib
import math
import os
import stat
import subprocess
import time

import recovery_bootargs as boot
from recovery_panic_control import validate_scope

LIMIT=131072
STDOUT_PREFIX=22*1024
STDERR_PREFIX=2*1024
TOOL='/usr/bin/sample'


def _sha(raw): return hashlib.sha256(raw).hexdigest()


def _tool_sha():
    fd=None
    try:
        fd=os.open(TOOL,os.O_RDONLY|os.O_NOFOLLOW)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=16*1024*1024: return None
        with os.fdopen(fd,'rb') as stream:
            fd=None; raw=stream.read(16*1024*1024+1); after=os.fstat(stream.fileno())
        if len(raw)!=info.st_size or (info.st_ino,info.st_mtime_ns,info.st_size)!=(after.st_ino,after.st_mtime_ns,after.st_size): return None
        return _sha(raw)
    except OSError: return None
    finally:
        if fd is not None: os.close(fd)


class Sampler:
    def __init__(self, scope, *, deadline, read=None):
        validate_scope(scope)
        if type(deadline) not in (int,float) or not math.isfinite(deadline): raise ValueError('sample_deadline_invalid')
        self._deadline=deadline
        self._read=boot.capture if read is None else read
        self._attempted=False
        self._fragments={'stdout':b'','stderr':b''}
        self._fact={'scope':dict(scope),'status':'not_requested','target_pid':None,'profiler':'sample','profiler_sha256':None,
                    'timeout_seconds':8,'output_limit':LIMIT,'elapsed_ms':0,'exit_code':None,'cleanup':'not_started',
                    'stdout_bytes':None,'stdout_sha256':None,'stderr_bytes':None,'stderr_sha256':None,
                    'stderr_available':False,'prefix_bytes':0,'prefix_sha256':_sha(b''),
                    'original_timeout_seconds':None,'original_output_bytes':None,'original_output_sha256':None}

    def __call__(self, pid, frozen):
        if self._attempted: raise ValueError('sample_already_attempted')
        if type(pid) is not int or not 0<pid<2**31: raise ValueError('sample_pid_invalid')
        if (type(frozen) is not dict or set(frozen)!={'timeout_seconds','stdout','stderr'} or
                type(frozen['timeout_seconds']) not in (int,float) or not math.isfinite(frozen['timeout_seconds']) or frozen['timeout_seconds']<=0 or
                any(value is not None and type(value) is not bytes for value in (frozen['stdout'],frozen['stderr']))):
            raise ValueError('sample_timeout_invalid')
        original=(frozen['stdout'] or b'')+(frozen['stderr'] or b'')
        if len(original)>4096: raise ValueError('sample_timeout_invalid')
        self._attempted=True; started=time.monotonic()
        self._fact.update(target_pid=pid,original_timeout_seconds=frozen['timeout_seconds'])
        if frozen['stdout'] is not None or frozen['stderr'] is not None:
            self._fact.update(original_output_bytes=len(original),original_output_sha256=_sha(original))
        if self._deadline-time.monotonic()<12:
            self._fact['status']='no_budget'; return
        self._fact['profiler_sha256']=_tool_sha()
        if self._deadline-time.monotonic()<12:
            self._fact['status']='no_budget'; return
        out=err=None; limit_error=False
        self._fact['cleanup']='unknown'
        try:
            out=self._read([TOOL,str(pid),'1','10','-mayDie','-file','/dev/stdout'],LIMIT,timeout=8,capture_stderr=True)
            if type(out) is not bytes or len(out)>LIMIT: raise ValueError('sample_output_invalid')
            self._fact.update(status='observed',exit_code=0,cleanup='reaped')
        except subprocess.CalledProcessError as error:
            out,err=error.output,error.stderr
            code=error.returncode
            self._fact.update(status='failed',exit_code=code if type(code) is int and -255<=code<=255 else None,cleanup='reaped')
        except subprocess.TimeoutExpired as error:
            out,err=error.output,error.stderr
            self._fact.update(status='timeout',cleanup='reaped' if type(out) is bytes or type(err) is bytes else 'unknown')
        except boot.CaptureLimit as error:
            out,err=error.output,error.stderr; limit_error=True
            self._fact.update(status='output_limit',cleanup='reaped')
        except OSError: self._fact['status']='unavailable'
        except (KeyboardInterrupt,SystemExit): self._fact['status']='interrupted'
        except BaseException: self._fact['status']='failed'
        finally:
            self._fact['elapsed_ms']=max(0,int((time.monotonic()-started)*1000))
        if out is not None and type(out) is not bytes or err is not None and type(err) is not bytes:
            out=err=None;self._fact.update(status='failed',cleanup='unknown')
        if len(out or b'')+len(err or b'')>LIMIT:
            if limit_error:
                # Counts/hashes describe retained bounded bytes, not all produced output.
                out=(out or b'')[:LIMIT-min(len(err or b''),STDERR_PREFIX)]
                err=(err or b'')[:LIMIT-len(out)]
            else:
                out=err=None;self._fact.update(status='failed',cleanup='unknown')
        if out is not None: self._fact.update(stdout_bytes=len(out),stdout_sha256=_sha(out))
        if err is not None: self._fact.update(stderr_available=True,stderr_bytes=len(err),stderr_sha256=_sha(err))
        self._fragments={'stdout':(out or b'')[:STDOUT_PREFIX],'stderr':(err or b'')[:STDERR_PREFIX]}
        prefix=self._fragments['stdout']+self._fragments['stderr']
        self._fact.update(prefix_bytes=len(prefix),prefix_sha256=_sha(prefix))

    def public_fact(self): return copy.deepcopy(self._fact)

    def private_fragments(self): return dict(self._fragments)
