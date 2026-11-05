import importlib.util
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('reboot_panic', Path(__file__).with_name('recovery_reboot_panic.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class RebootPanic(unittest.TestCase):
    def context(self):
        return dict(actions='true', repo='Code-Hex/vz-ci-test', ref='refs/heads/main', event='workflow_dispatch',
                    runner_environment='github-hosted', run_id='123', attempt='1', sha='a'*40,
                    trigger='reboot-quick', debug_boot=True, debug_source='bootplist', after_debug_boot='panic-nonce-syscall')

    def test_context_and_clean_environment(self):
        ctx = self.context(); c.validate_context(ctx)
        env = c.child_env(ctx, 'b'*64, 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')
        self.assertEqual(env['RECOVERY_AFTER_DEBUG_BOOT'], 'panic-nonce-syscall')
        self.assertNotIn('GITHUB_TOKEN', env)
        for key, value in (('debug_boot', 1), ('after_debug_boot', 'panic-nonce-usdt'), ('sha', 'A'*40), ('attempt', True)):
            with self.subTest(key=key), self.assertRaises(ValueError): c.validate_context({**ctx, key:value})

    def test_fire_rejects_invalid_context_before_private_io(self):
        scope={'binding':'123/1/'+'a'*40,'nonce':'b'*64,'baseline':'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
               'source_identity':'c'*64,'debug_boot_uuid':'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'}
        with self.assertRaises(ValueError):
            c.fire('/missing',scope,{},lambda *_:self.fail('write'),lambda _:None,lambda _:self.fail('ACK'),
                   lambda:self.fail('boot read'),context={},deadline=time.monotonic()+5)

    def test_ready_and_returned_are_exact(self):
        nonce='b'*64
        self.assertEqual(c.ready_line(nonce,123), ('REBOOT_READY 123 vz-reboot-panic:'+nonce+':123\n').encode())
        self.assertEqual(c.parse_returned(b'REBOOT_RETURNED -1 1\n'), (-1,1))
        for raw in (b'REBOOT_RETURNED -1 1\n\n', b'REBOOT_RETURNED -1 1\r\n', b'REBOOT_RETURNED -1 -1\n', b'REBOOT_RETURNED 0 True\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): c.parse_returned(raw)

    def save(self, path, raw):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())

    def fixture(self, directory, body=None):
        private=directory/'panic-control'; private.mkdir(mode=0o700)
        source=('#!'+sys.executable+'\nimport os,sys,time\n'
            "nonce=os.environ['VZ_RECOVERY_NONCE']; pid=os.getpid()\n"
            "print('REBOOT_READY '+str(pid)+' vz-reboot-panic:'+nonce+':'+str(pid),flush=True)\n"
            "value=os.read(0,1)\n"
            "if value==b'Q': sys.exit(0)\n"
            "if value!=b'G': sys.exit(65)\n"+
            (body or "print('REBOOT_RETURNED -1 1',flush=True)\nsys.exit(70)\n"))
        helper=private/'helper'; helper.write_text(source); helper.chmod(0o700)
        self.save(private/'prepared.json',b'{}')
        scope={'binding':'123/1/'+'a'*40,'nonce':'b'*64,'baseline':'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
               'source_identity':'c'*64,'debug_boot_uuid':'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'}
        return helper,scope,c.child_env(self.context(),scope['nonce'],scope['debug_boot_uuid'])

    def test_owned_ready_q_has_no_release_and_is_reaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            helper,scope,env=self.fixture(Path(tmp))
            c._preflight(helper,scope['nonce'],env,time.monotonic()+3)
            self.assertFalse((Path(tmp)/'panic-control'/'release-attempt.json').exists())

    def test_native_owned_release_is_once_and_return_is_not_permission_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); helper,scope,env=self.fixture(directory); triggers=[]
            def ack(trigger):
                self.assertEqual(set(trigger),{'scope','helper_sha256','helper_pid','ready'})
                triggers.append(trigger); return True
            result=c._fire_owned(helper,directory,scope,'d'*64,env,self.save,lambda _:None,ack,
                                 lambda:scope['debug_boot_uuid'],time.monotonic()+5)
            self.assertEqual((result['phase'],result['result'],result['errno'],result['helper_exit']),('returned',-1,1,70))
            self.assertTrue(result['output_complete']); self.assertEqual(len(triggers),1)
            self.assertEqual(c.json.loads((directory/'panic-control'/'release-attempt.json').read_text()),triggers[0])
            with self.assertRaises(FileExistsError):
                c._fire_owned(helper,directory,scope,'d'*64,env,self.save,lambda _:None,ack,
                              lambda:scope['debug_boot_uuid'],time.monotonic()+5)
            self.assertEqual(len(triggers),1)
            with self.assertRaises(ProcessLookupError): os.kill(triggers[0]['helper_pid'],0)

    def test_ack_refusal_and_expired_callback_never_write_g(self):
        for expired in (False,True):
            with self.subTest(expired=expired),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);helper,scope,env=self.fixture(directory);pids=[]
                deadline=time.monotonic()+2.15 if expired else time.monotonic()+5
                def ack(trigger):
                    pids.append(trigger['helper_pid'])
                    if expired: time.sleep(0.2)
                    return expired
                result=c._fire_owned(helper,directory,scope,'d'*64,env,self.save,lambda _:None,ack,
                                     lambda:scope['debug_boot_uuid'],deadline)
                self.assertEqual(result['phase'],'not_released')
                self.assertFalse((directory/'panic-control'/'release-attempt.json').exists())
                with self.assertRaises(ProcessLookupError): os.kill(pids[0],0)

    def test_after_release_delay_and_overflow_still_wait_for_same_owned_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            helper,scope,env=self.fixture(directory,"time.sleep(0.15)\nos.write(1,b'X'*70000)\nprint('REBOOT_RETURNED -1 1',flush=True)\nsys.exit(70)\n")
            started=time.monotonic()
            result=c._fire_owned(helper,directory,scope,'d'*64,env,self.save,lambda _:None,lambda _:True,
                                 lambda:scope['debug_boot_uuid'],time.monotonic()+5)
            self.assertGreaterEqual(time.monotonic()-started,0.15)
            self.assertEqual(result['phase'],'unknown'); self.assertTrue(result['output_overflow'])
            self.assertEqual(result['helper_exit'],70)
            self.assertLessEqual(sum((directory/'panic-control'/name).stat().st_size for name in ('helper.stdout','helper.stderr')),65536)

    def test_pre_release_journal_failure_is_known_no_g_and_reaped(self):
        for where in ('save','sync'):
            with self.subTest(where=where),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);helper,scope,env=self.fixture(directory);pids=[]
                def ack(trigger): pids.append(trigger['helper_pid']); return True
                def sync(path):
                    if where=='sync' and (path/'release-attempt.json').exists(): raise OSError('synthetic fsync failure')
                # once_record owns the actual O_EXCL write; a preexisting target models its creation failure.
                if where=='save': self.save(directory/'panic-control'/'release-attempt.json',b'{}')
                with self.assertRaises(OSError):
                    c._fire_owned(helper,directory,scope,'d'*64,env,self.save,sync,ack,
                                  lambda:scope['debug_boot_uuid'],time.monotonic()+5)
                self.assertEqual(len(pids),1)
                with self.assertRaises(ProcessLookupError): os.kill(pids[0],0)

    def test_release_pipe_failure_is_unknown_and_never_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); helper,scope,env=self.fixture(directory); pids=[]; stopped=[]
            def ack(trigger): pids.append(trigger['helper_pid']); return True
            def sync(path):
                if not stopped and (path/'release-attempt.json').exists():
                    stopped.append(True)
                    os.kill(pids[0],signal.SIGTERM)
                    time.sleep(0.05)
            result=c._fire_owned(helper,directory,scope,'d'*64,env,self.save,sync,ack,
                                 lambda:scope['debug_boot_uuid'],time.monotonic()+5)
            self.assertEqual((result['phase'],result['release_status'],result['helper_exit']),('unknown','unknown',-signal.SIGTERM))
            self.assertIsNone(result['result']); self.assertIsNone(result['errno'])
            self.assertEqual(len(pids),1)
            with self.assertRaises(ProcessLookupError): os.kill(pids[0],0)

    def test_after_release_read_signal_and_select_faults_keep_owned_child(self):
        for kind in ('read','select','setup','sleep'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp); helper,scope,env=self.fixture(directory,"time.sleep(0.12)\nprint('REBOOT_RETURNED -1 1',flush=True)\nsys.exit(70)\n");pids=[]; faults=[]
                def read(fd,n):
                    if len(faults)<2:
                        faults.append(True)
                        if len(faults)==1: raise KeyboardInterrupt()
                        raise OSError('synthetic pipe read failure')
                    return os.read(fd,n)
                def broken_select(*_a): raise OSError('synthetic select failure')
                def broken_setup(*_a): raise OSError('synthetic setup failure')
                def interrupted_sleep(seconds):
                    if not faults:
                        faults.append(True); raise KeyboardInterrupt()
                    time.sleep(seconds)
                def drain(child,**kwargs):
                    seam={'read':{'read_fn':read},'select':{'select_fn':broken_select},
                          'setup':{'set_blocking_fn':broken_setup},
                          'sleep':{'select_fn':broken_select,'sleep_fn':interrupted_sleep}}[kind]
                    return c._drain(child,**kwargs,**seam)
                def ack(trigger): pids.append(trigger['helper_pid']); return True
                result=c._fire_owned(helper,directory,scope,'d'*64,env,self.save,lambda _:None,ack,
                                     lambda:scope['debug_boot_uuid'],time.monotonic()+5,drain=drain)
                self.assertEqual(result['phase'],'unknown')
                self.assertEqual(result['helper_exit'],70)
                self.assertGreater(result['ownership_faults'],0)
                self.assertFalse(result['output_complete'])
                self.assertIn(b'REBOOT_RETURNED -1 1\n',(directory/'panic-control'/'helper.stdout').read_bytes())
                with self.assertRaises(ProcessLookupError): os.kill(pids[0],0)

    def test_pre_ack_exception_reaps_only_owned_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); helper,scope,env=self.fixture(directory); pids=[]
            def ack(trigger): pids.append(trigger['helper_pid']); raise OSError('synthetic ACK failure')
            with self.assertRaises(OSError):
                c._fire_owned(helper,directory,scope,'d'*64,env,self.save,lambda _:None,ack,
                              lambda:scope['debug_boot_uuid'],time.monotonic()+5)
            self.assertFalse((directory/'panic-control'/'release-attempt.json').exists())
            with self.assertRaises(ProcessLookupError): os.kill(pids[0],0)

    @unittest.skipUnless(sys.platform=='darwin','Apple compiler/signing boundary')
    def test_native_fixed_source_build_signature_and_receipt_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); source=Path(__file__).resolve().parent.parent/'probes'/'reboot_panic.c'
            built=c.build(directory,'b'*64,self.save,lambda _:None,context=self.context(),source_path=source)
            self.assertEqual(set(built),c.RECEIPT_KEYS)
            self.assertIs(built['permission_verified'],False)
            self.assertEqual(built['preflight_status'],'not_run')
            self.assertEqual(c.validate_built(directory,'b'*64,built,context=self.context()),directory/'panic-control'/'helper')
            for change in ({'flags':True},{'flags':11264},{'permission_verified':0},{'preflight_status':'passed'},
                           {'control_kind':'usdt-v1'},{'extra':'private'}):
                with self.subTest(change=change),self.assertRaises(ValueError):
                    c.validate_built(directory,'b'*64,{**built,**change},context=self.context())
            prepared={**built,'preflight_status':'passed'}
            self.save(directory/'panic-control'/'prepared.json',c.canonical(prepared))
            self.assertEqual(c.validate_prepared(directory,'b'*64,prepared,context=self.context()),directory/'panic-control'/'helper')
            for record in (built,{**prepared,'flags':True},{**prepared,'permission_verified':0},{**prepared,'control_kind':'usdt-v1'}):
                with self.subTest(record=record),self.assertRaises(ValueError):
                    c.validate_prepared(directory,'b'*64,record,context=self.context())
            native=directory/'guard-helper'
            subprocess.run(['/usr/bin/xcrun','clang','-Wall','-Wextra','-Werror',str(source),'-o',str(native)],check=True,capture_output=True)
            denied=subprocess.run([str(native)],input=b'Q',capture_output=True,env={'PATH':'/usr/bin:/bin'},timeout=3)
            self.assertEqual((denied.returncode,denied.stdout,denied.stderr),(77,b'',b'REBOOT_GUARD_FAILED\n'))

if __name__ == '__main__': unittest.main()
