import hashlib
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import time
import unittest

import recovery_bootargs as boot
import recovery_kernel_sample as sample

SCOPE={'binding':'123/1/'+'a'*40,'nonce':'b'*64,'baseline':'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
       'source_identity':'c'*64,'debug_boot_uuid':'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'}
FROZEN={'timeout_seconds':30,'stdout':b'','stderr':b''}


class KernelSample(unittest.TestCase):
    def test_fixed_sampler_read_public_hashes_and_private_prefix(self):
        calls=[]
        def read(argv,limit,*,timeout,capture_stderr):
            self.assertEqual(argv,['/usr/bin/sample','1234','1','10','-mayDie','-file','/dev/stdout'])
            self.assertEqual((limit,timeout,capture_stderr),(131072,8,True));calls.append(1)
            return boot.capture([sys.executable,'-c','import sys;sys.stdout.write("s"*70000);sys.stderr.write("warning")'],limit,timeout,capture_stderr=True)
        observer=sample.Sampler(SCOPE,deadline=time.monotonic()+30,read=read);observer(1234,FROZEN)
        fact=observer.public_fact();private=observer.private_fragments()
        self.assertEqual((fact['status'],fact['cleanup'],fact['stdout_bytes']),('observed','reaped',70000))
        self.assertEqual(fact['stdout_sha256'],hashlib.sha256(b's'*70000).hexdigest())
        self.assertFalse(fact['stderr_available']);self.assertIsNone(fact['stderr_bytes']);self.assertIsNone(fact['stderr_sha256'])
        self.assertEqual(private,{'stdout':b's'*22528,'stderr':b''})
        self.assertEqual(fact['original_output_sha256'],hashlib.sha256(b'').hexdigest())
        self.assertEqual(fact['original_output_bytes'],0)
        with self.assertRaises(ValueError): observer(1234,FROZEN)
        self.assertEqual(calls,[1])
        fact['scope']['nonce']='modified';self.assertEqual(observer.public_fact()['scope'],SCOPE)

    def test_native_failed_reader_keeps_bounded_stderr_without_public_raw(self):
        def read(argv,limit,*,timeout,capture_stderr):
            return boot.capture([sys.executable,'-c','import sys;sys.stdout.write("s"*30000);sys.stderr.write("e"*4000);sys.exit(1)'],limit,timeout,capture_stderr=True)
        observer=sample.Sampler(SCOPE,deadline=time.monotonic()+30,read=read);observer(1234,FROZEN)
        fact=observer.public_fact();private=observer.private_fragments()
        self.assertEqual((fact['status'],fact['exit_code'],fact['cleanup']),('failed',1,'reaped'))
        self.assertTrue(fact['stderr_available']);self.assertEqual(fact['stderr_bytes'],4000)
        self.assertEqual(private,{'stdout':b's'*22528,'stderr':b'e'*2048})
        self.assertEqual(fact['prefix_bytes'],24576)
        self.assertEqual(fact['prefix_sha256'],hashlib.sha256(private['stdout']+private['stderr']).hexdigest())
        self.assertNotIn('eeee',str(fact));self.assertNotIn('ssss',str(fact))

    def test_limit_keeps_reason_reap_and_bounded_prefix(self):
        for overrun in (False,True):
            with self.subTest(overrun=overrun):
                def read(argv,limit,*,timeout,capture_stderr):
                    if overrun: raise boot.CaptureLimit(b's'*(limit+1),b'e'*4096)
                    return boot.capture([sys.executable,'-c','import sys;sys.stdout.write("s"*200000)'],limit,timeout,capture_stderr=True)
                observer=sample.Sampler(SCOPE,deadline=time.monotonic()+30,read=read);observer(1234,FROZEN)
                fact=observer.public_fact();private=observer.private_fragments()
                self.assertEqual((fact['status'],fact['cleanup']),('output_limit','reaped'))
                self.assertLessEqual(fact['stdout_bytes']+fact['stderr_bytes'],131072)
                self.assertEqual(private['stdout'],b's'*22528)
                self.assertEqual(private['stderr'],b'e'*2048 if overrun else b'')

    def test_sampler_outcomes_never_replace_getter_timeout_and_reap_owned_children(self):
        for case in ('success','failed','timeout','limit','interrupt'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                pidfile=Path(tmp)/'sampler.pid'
                def read(argv,limit,*,timeout,capture_stderr):
                    self.assertEqual((limit,timeout,capture_stderr),(131072,8,True))
                    program='import os,sys,time;open('+repr(str(pidfile))+',"w").write(str(os.getpid()));'
                    if case=='success': program+='print("private sample prefix")'
                    elif case=='failed': program+='sys.stderr.write("private permission failure");sys.exit(1)'
                    elif case=='limit': program+='sys.stdout.write("x"*200000)'
                    else: program+='time.sleep(10)'
                    if case!='interrupt': return boot.capture([sys.executable,'-c',program],limit,.04 if case=='timeout' else 1,capture_stderr=True)
                    previous=signal.getsignal(signal.SIGALRM)
                    def interrupted(*_): raise KeyboardInterrupt()
                    signal.signal(signal.SIGALRM,interrupted);signal.setitimer(signal.ITIMER_REAL,.15)
                    try: return boot.capture([sys.executable,'-c',program],limit,1,capture_stderr=True)
                    finally: signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
                observer=sample.Sampler(SCOPE,deadline=time.monotonic()+30,read=read)
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    boot.capture([sys.executable,'-c','import time;time.sleep(10)'],4096,.02,capture_stderr=True,on_timeout=observer)
                self.assertEqual((caught.exception.timeout,caught.exception.output,caught.exception.stderr),(.02,b'',b''))
                fact=observer.public_fact()
                self.assertEqual(fact['status'],{'success':'observed','failed':'failed','timeout':'timeout','limit':'output_limit','interrupt':'interrupted'}[case])
                self.assertEqual(fact['original_timeout_seconds'],.02)
                self.assertEqual(fact['original_output_bytes'],0)
                self.assertEqual(fact['original_output_sha256'],hashlib.sha256(b'').hexdigest())
                for pid in (fact['target_pid'],int(pidfile.read_text())):
                    with self.assertRaises(ProcessLookupError): os.kill(pid,0)

    @unittest.skipUnless(sys.platform=='darwin' and Path('/usr/bin/sample').exists(),'Apple sample owned fixture')
    def test_real_sample_pipe_on_only_our_waiting_python(self):
        child=subprocess.Popen([sys.executable,'-c','import sys;sys.stdin.buffer.read(1)'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            observer=sample.Sampler(SCOPE,deadline=time.monotonic()+30);observer(child.pid,FROZEN)
            fact=observer.public_fact();private=observer.private_fragments()
            self.assertEqual((fact['status'],fact['cleanup'],fact['exit_code']),('observed','reaped',0))
            self.assertGreater(fact['stdout_bytes'],0);self.assertLessEqual(fact['stdout_bytes'],131072)
            self.assertIsNotNone(fact['profiler_sha256'])
            self.assertTrue(b'Call graph' in private['stdout'])
            self.assertIsNone(child.poll())
        finally:
            if child.poll() is None: child.stdin.write(b'Q');child.stdin.flush()
            child.wait(timeout=2);child.stdin.close()

    def test_no_budget_and_invalid_binding_start_nothing(self):
        def forbidden(*_a,**_k): self.fail('sampler started without budget')
        observer=sample.Sampler(SCOPE,deadline=time.monotonic()+11,read=forbidden);observer(1234,FROZEN)
        self.assertEqual((observer.public_fact()['status'],observer.public_fact()['cleanup']),('no_budget','not_started'))
        for value in (True,0,-1):
            with self.assertRaises(ValueError): sample.Sampler(SCOPE,deadline=time.monotonic()+30,read=forbidden)(value,FROZEN)
        with self.assertRaises(ValueError): sample.Sampler({**SCOPE,'extra':'secret'},deadline=time.monotonic()+30)


if __name__=='__main__':unittest.main()
