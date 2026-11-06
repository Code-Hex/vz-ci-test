import hashlib
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import recovery_begin_panic as b

CTX={'actions':'true','repo':'Code-Hex/vz-ci-test','ref':'refs/heads/main','event':'workflow_dispatch',
     'runner_environment':'github-hosted','run_id':'123','attempt':'1','sha':'a'*40,'trigger':'reboot-quick',
     'debug_boot':True,'debug_source':'bootplist','after_debug_boot':'panic-nonce-begin'}
NONCE='b'*64
B2='BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'
SCOPE={'binding':'123/1/'+'a'*40,'nonce':NONCE,'baseline':'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
       'source_identity':'c'*64,'debug_boot_uuid':B2}


def save(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


class BeginControl(unittest.TestCase):
    def test_fixed_program_and_strict_returned_lines(self):
        program=b.program(NONCE)
        self.assertIs(type(program),bytes)
        expected=('dtrace:::ERROR { printf("VZ_BEGIN_FAULT '+NONCE+' %u\\n", (uint32_t)arg4); exit(71); }\n'
                  'dtrace:::BEGIN { panic(); printf("VZ_BEGIN_AFTER_PANIC '+NONCE+'\\n"); exit(70); }\n').encode()
        self.assertEqual(program,expected)
        self.assertIn(('VZ_BEGIN_FAULT '+NONCE).encode(),program)
        self.assertIn(('VZ_BEGIN_AFTER_PANIC '+NONCE).encode(),program)
        self.assertIn(b'panic();',program)
        self.assertEqual(b.parse_returned(('VZ_BEGIN_AFTER_PANIC '+NONCE+'\n\n').encode(),70,NONCE),('after_action',None))
        self.assertEqual(b.parse_returned(('VZ_BEGIN_FAULT '+NONCE+' 8\n\n').encode(),71,NONCE),('fault',8))
        for raw,code in ((('VZ_BEGIN_AFTER_PANIC '+NONCE+'\n').encode(),70),
                         (('VZ_BEGIN_AFTER_PANIC '+NONCE+'\n\n\n').encode(),70),
                         (('VZ_BEGIN_FAULT '+NONCE+' 8\n\n').encode(),70),
                         (('VZ_BEGIN_FAULT '+NONCE+' 08\n\n').encode(),71),
                         (('VZ_BEGIN_AFTER_PANIC '+'a'*64+'\n\n').encode(),70)):
            with self.subTest(code=code),self.assertRaises(ValueError):b.parse_returned(raw,code,NONCE)

    def fixture(self,directory,*,policy='0',compile_code=0):
        built=b.build(directory,NONCE,save,lambda _:None,context=CTX);calls=[]
        def run(argv,private,label,end):
            calls.append(argv)
            if argv[0]=='/usr/sbin/sysctl':
                self.assertEqual(argv,['/usr/sbin/sysctl','-n','kern.bootsessionuuid'])
                code='print('+repr(B2)+')'
            else:
                self.assertEqual(argv,['/usr/sbin/dtrace','-w','-e','-q','-n',b.program(NONCE).decode()])
                code='raise SystemExit('+str(compile_code)+')'
            return b._command([sys.executable,'-c',code],private,label,end)
        def read(argv,limit,*,timeout,capture_stderr):
            self.assertEqual((limit,timeout,capture_stderr),(4096,5,True))
            self.assertEqual(argv,['/usr/sbin/dtrace','-q','-x','errtags','-n',b.boot.kernel_field_program('dtrace_destructive_disallow')])
            return b.boot.capture([sys.executable,'-c',"print('VZKSTATE v1 dtrace_destructive_disallow i32 "+policy+"\\n')"],limit,timeout,capture_stderr=True)
        return built,run,read,calls

    def prepare_fixture(self,directory):
        built,run,read,calls=self.fixture(directory)
        prepared=b.prepare(directory,NONCE,save,lambda _:None,context=CTX,deadline=time.monotonic()+40,run_command=run,read=read)
        return built,prepared,calls

    def test_real_owned_compile_seam_and_closed_built_prepared(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);built,prepared,calls=self.prepare_fixture(directory)
            self.assertEqual(set(built),{'protocol','control_kind','source_hashes','context_sha256','nonce_sha256','program_sha256','dtrace_sha256','permission_verified','build_status'})
            self.assertEqual(set(prepared),set(built)|{'compile_status','debug_boot_uuid','destructive_policy'})
            self.assertEqual(prepared['destructive_policy'],{'status':'observed','value':0})
            self.assertEqual(prepared['debug_boot_uuid'],B2)
            self.assertIs(prepared['permission_verified'],False)
            self.assertEqual(b.checked_prepared(prepared,NONCE,context=CTX),prepared)
            self.assertEqual(b.validate_prepared(directory,NONCE,prepared,context=CTX),Path('/usr/sbin/dtrace'))
            self.assertEqual([argv[1:5] for argv in calls if argv[0]=='/usr/sbin/dtrace'],[['-w','-e','-q','-n']])
            self.assertFalse((directory/'panic-control'/'launch-attempt.json').exists())
            for change in ({'permission_verified':0},{'helper_pid':123},{'observe_status':'passed'},
                           {'destructive_policy':{'status':'observed','value':False}},
                           {'destructive_policy':{'status':'observed','value':1}},{'control_kind':'usdt-v1'},
                           {'program_sha256':'0'*64},{'debug_boot_uuid':'invalid'}):
                with self.subTest(change=change),self.assertRaises(ValueError):
                    b.checked_prepared({**prepared,**change},NONCE,context=CTX)
            with self.assertRaises(ValueError):b.checked_prepared(prepared,NONCE,context={**CTX,'after_debug_boot':'panic-nonce-usdt'})
            (directory/'panic-control'/'program.d').write_bytes(b'changed')
            with self.assertRaises(ValueError):b.validate_prepared(directory,NONCE,prepared,context=CTX)

    def test_prepare_policy_and_compile_failure_never_launch(self):
        for policy,code in (('1',0),('-1',0),('0',1)):
            with self.subTest(policy=policy,code=code),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);_,run,read,calls=self.fixture(directory,policy=policy,compile_code=code)
                with self.assertRaises(ValueError):
                    b.prepare(directory,NONCE,save,lambda _:None,context=CTX,deadline=time.monotonic()+40,run_command=run,read=read)
                self.assertFalse((directory/'panic-control'/'prepared.json').exists())
                self.assertFalse((directory/'panic-control'/'launch-attempt.json').exists())
                self.assertEqual(any(argv[0]=='/usr/sbin/dtrace' for argv in calls),policy=='0')

    def test_pure_prepared_requires_no_installed_tool_and_fire_binds_b2(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);_,prepared,_=self.prepare_fixture(directory)
            actual=b.DTRACE
            try:
                b.DTRACE='/not-installed/dtrace'
                self.assertEqual(b.checked_prepared(prepared,NONCE,context=CTX),prepared)
            finally:b.DTRACE=actual
            starts=[]
            def forbidden(*_a,**_k):starts.append(1);self.fail('wrong B2 launched child')
            with self.assertRaises(ValueError):
                b.fire(directory,SCOPE,prepared,save,lambda _:None,forbidden,
                       lambda:'CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC',context=CTX,deadline=time.monotonic()+5,start_child=forbidden)
            self.assertEqual(starts,[])

    def test_prepare_boot_change_prevents_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);_,run,read,_=self.fixture(directory)
            def changed(argv,private,label,end):
                if label=='prepared-boot':
                    return b._command([sys.executable,'-c',"print('CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC')"],private,label,end)
                return run(argv,private,label,end)
            with self.assertRaises(ValueError):
                b.prepare(directory,NONCE,save,lambda _:None,context=CTX,deadline=time.monotonic()+40,run_command=changed,read=read)
            self.assertFalse((directory/'panic-control'/'prepared.json').exists())

    def starter(self,nonce,code,*,pids,delay=0,output_limit=False):
        def start(argv,**kwargs):
            self.assertEqual(argv,['/usr/sbin/dtrace','-w','-q','-n',b.program(nonce).decode()])
            self.assertEqual(kwargs['stdin'],subprocess.DEVNULL)
            row=('VZ_BEGIN_AFTER_PANIC '+nonce+'\n\n') if code==70 else ('VZ_BEGIN_FAULT '+nonce+' 8\n\n')
            source='import sys,time;time.sleep('+str(delay)+');sys.stdout.write('+repr('x'*70000 if output_limit else row)+');raise SystemExit('+str(code)+')'
            child=subprocess.Popen([sys.executable,'-c',source],**kwargs);pids.append(child.pid);return child
        return start

    def test_single_owned_after_action_and_fault_returns_are_not_panic_proof(self):
        for code,outcome in ((70,'after_action'),(71,'fault')):
            with self.subTest(code=code),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);_,prepared,_=self.prepare_fixture(directory);pids=[];triggers=[]
                def ack(trigger):triggers.append(trigger);return True
                result=b.fire(directory,SCOPE,prepared,save,lambda _:None,ack,lambda:B2,context=CTX,
                              deadline=time.monotonic()+5,start_child=self.starter(NONCE,code,pids=pids))
                self.assertEqual((result['phase'],result['outcome'],result['dtrace_exit']),('returned',outcome,code))
                self.assertEqual(set(triggers[0]),{'scope','program_sha256','dtrace_sha256','prepared'})
                self.assertIs(triggers[0]['prepared'],True)
                self.assertEqual(json.loads((directory/'panic-control'/'launch-attempt.json').read_text()),triggers[0])
                self.assertEqual(len(pids),1)
                with self.assertRaises(ProcessLookupError):os.kill(pids[0],0)
                with self.assertRaises(FileExistsError):
                    b.fire(directory,SCOPE,prepared,save,lambda _:None,ack,lambda:B2,context=CTX,
                           deadline=time.monotonic()+5,start_child=self.starter(NONCE,code,pids=pids))
                self.assertEqual(len(pids),1)

    def test_ack_deadline_and_launch_journal_failure_start_no_child(self):
        for case in ('refuse','deadline','save','sync'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);_,prepared,_=self.prepare_fixture(directory);starts=[]
                def start(*_a,**_k):starts.append(True);self.fail('prelaunch failure spawned child')
                def ack(_):
                    if case=='deadline':time.sleep(.08)
                    return case!='refuse'
                def sync(path):
                    if case=='sync' and (path/'launch-attempt.json').exists():raise OSError('synthetic fsync failure')
                if case=='save':save(directory/'panic-control'/'launch-attempt.json',b'{}')
                kwargs={'context':CTX,'deadline':time.monotonic()+(.04 if case=='deadline' else 5),'start_child':start}
                if case in ('save','sync'):
                    with self.assertRaises(OSError):b.fire(directory,SCOPE,prepared,save,sync,ack,lambda:B2,**kwargs)
                else:self.assertEqual(b.fire(directory,SCOPE,prepared,save,sync,ack,lambda:B2,**kwargs)['phase'],'not_launched')
                self.assertEqual(starts,[])

    def test_after_launch_read_signal_faults_and_overflow_reap_same_child(self):
        for case in ('fault','overflow','launch_unknown'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);_,prepared,_=self.prepare_fixture(directory);pids=[];faults=[]
                def reader(child):
                    if not faults and case=='fault':faults.append(True);raise KeyboardInterrupt()
                    return b.drain_owner._drain(child)
                start=self.starter(NONCE,70,pids=pids,delay=.08,output_limit=case=='overflow')
                if case=='launch_unknown':
                    def start(*_a,**_k):pids.append(None);raise OSError('synthetic Popen uncertainty')
                result=b.fire(directory,SCOPE,prepared,save,lambda _:None,lambda _:True,lambda:B2,context=CTX,
                              deadline=time.monotonic()+5,start_child=start,drain=reader)
                self.assertEqual(result['phase'],'unknown');self.assertEqual(len(pids),1)
                if case!='launch_unknown':
                    with self.assertRaises(ProcessLookupError):os.kill(pids[0],0)
                    self.assertFalse(result['output_complete'])
                if case=='overflow':self.assertTrue(result['output_overflow'])
                if case=='fault':self.assertEqual(result['ownership_faults'],1)

if __name__=='__main__':unittest.main()
