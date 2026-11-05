import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import kernel_state_readonly as g

HERE=Path(__file__).resolve().parent
ENV={'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':'Code-Hex/vz-ci-test',
     'GITHUB_REF':'refs/heads/main','GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,
     'RUNNER_ENVIRONMENT':'github-hosted'}


def report():
    error={'reason':'unknown','exit_code':None,'output_bytes':None,'output_sha256':None,'tags':[]}
    value={'protocol':'kernel-field-readonly-v2','scope':'normal_boot_no_staging','context':g.checked_context(ENV),
        'sources':{name:'a'*64 for name in ('script','workflow','bootargs','registry')},
        'kernel':{'live_uuid':g.KERNEL_UUID,'file_uuid':g.KERNEL_UUID},
        'boot_profile':{'status':'unavailable'},
        'fields':{name:{'status':'unavailable','error':dict(error)} for name in g.FIELD_NAMES},'completed':True}
    value['readings']=[{'attempt':attempt,'budget_seconds':budget,'elapsed_ms':0,
                        'result':copy.deepcopy(value['fields']['debug_boot_arg'])}
                       for attempt,budget in (('first',30),('repeat',5))]
    return value


class KernelState(unittest.TestCase):
    def test_exact_success_report_all_unknown_is_completed_without_mask_proof(self):
        value=report()
        self.assertEqual(g.validate_report(value),value)
        value['fields'].update(debug_boot_arg={'status':'observed','value':0x102000},
            dtrace_destructive_disallow={'status':'observed','value':-1},
            coprocessor_paniclog_flush={'status':'observed','value':False})
        value['readings'][0]['result']=copy.deepcopy(value['fields']['debug_boot_arg'])
        self.assertIs(g.validate_report(value)['fields']['coprocessor_paniclog_flush']['value'],False)
        for change in ({'raw':'private'},{'completed':1},{'scope':'B2_mask_proven'}):
            with self.assertRaises(g.GateFailure): g.validate_report({**value,**change})
        for field in ({'status':'observed','value':True},{'status':'observed','value':0,'error':{}},
                      {'status':'unavailable'},{'status':'unavailable','error':{**value['fields']['kdp_flag']['error'],'raw':'secret'}}):
            altered=copy.deepcopy(value); altered['fields']['debug_boot_arg']=field
            with self.assertRaises((g.GateFailure,ValueError)): g.validate_report(altered)
        for fields in ({}, {**value['fields'],'foreign':{'status':'observed','value':0}}):
            with self.assertRaises(g.GateFailure): g.validate_report({**value,'fields':fields})

    def test_boot_profile_and_kernel_schema_reject_wrong_types_raw_and_mismatch(self):
        value=report()
        profile={'status':'observed','debug_mask':0x102000,'nondebug_token_count':0,
                 'nondebug_sha256':'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'}
        self.assertEqual(g.validate_report({**value,'boot_profile':profile})['boot_profile'],profile)
        for change in ({'debug_mask':True},{'debug_mask':4294967296},{'nondebug_token_count':True},
                       {'nondebug_sha256':'bad'},{'raw':'private'}):
            with self.assertRaises(g.GateFailure): g.validate_report({**value,'boot_profile':{**profile,**change}})
        for kernel in ({'live_uuid':g.KERNEL_UUID}, {**value['kernel'],'file_uuid':'bad'},
                       {**value['kernel'],'raw_path':'/private/secret'}):
            with self.assertRaises(g.GateFailure): g.validate_report({**value,'kernel':kernel})

    def test_first_repeat_are_always_planned_and_first_result_is_not_overwritten(self):
        for first_failed in (False,True):
            with self.subTest(first_failed=first_failed):
                calls=[]
                def read(argv,limit,timeout,*,capture_stderr):
                    name=next(name for name in g.FIELD_NAMES if 'VZKSTATE v1 '+name+' ' in argv[-1])
                    self.assertEqual(argv,['/usr/sbin/dtrace','-q','-x','errtags','-n',g.boot.kernel_field_program(name)])
                    calls.append((name,timeout))
                    line='VZKSTATE v1 '+name+' '+g.boot.KERNEL_FIELDS[name][1]+' 0\n\n'
                    program='import sys; sys.stdout.write('+repr(line)+')'
                    if len(calls)==1 and first_failed: program+='; sys.stderr.write("[D_IDENT_UNDEF]"); sys.exit(1)'
                    return g.boot.capture([sys.executable,'-c',program],limit,timeout,capture_stderr=True)
                fields,readings=g.read_fields(read=read)
                self.assertEqual(calls,[('debug_boot_arg',30),('debug_boot_arg',5)]+[(name,5) for name in g.FIELD_NAMES[1:]])
                self.assertEqual(fields['debug_boot_arg'],readings[0]['result'])
                self.assertEqual(fields['debug_boot_arg']['status'],'unavailable' if first_failed else 'observed')
                self.assertEqual(readings[1]['result'],{'status':'observed','value':0})
                self.assertEqual([item['attempt'] for item in readings],['first','repeat'])
                self.assertTrue(all(type(item['elapsed_ms']) is int and 0<=item['elapsed_ms']<=140000 for item in readings))
                self.assertEqual(g.validate_report({**report(),'fields':fields,'readings':readings})['readings'],readings)

    def test_readings_schema_rejects_wrong_order_budget_elapsed_extra_and_first_mismatch(self):
        value=report()
        for readings in (list(reversed(value['readings'])),value['readings'][:1],value['readings']*2):
            with self.assertRaises(g.GateFailure): g.validate_report({**value,'readings':readings})
        for change in ({'budget_seconds':5},{'budget_seconds':True},{'elapsed_ms':True},{'elapsed_ms':-1},
                       {'elapsed_ms':140001},{'raw':'private'},{'result':{'status':'observed','value':0}}):
            readings=copy.deepcopy(value['readings']); readings[0].update(change)
            with self.assertRaises(g.GateFailure): g.validate_report({**value,'readings':readings})
        with self.assertRaises(g.GateFailure): g.validate_report({**value,'protocol':'kernel-field-readonly-v1'})

    def test_context_and_sources_reject_unknown_or_wrong_typed_metadata(self):
        for change in ({'GITHUB_ACTIONS':'false'},{'GITHUB_EVENT_NAME':'pull_request'},{'GITHUB_REPOSITORY':'foreign'},
                       {'GITHUB_REF':'refs/heads/other'},{'GITHUB_RUN_ATTEMPT':'0'},{'GITHUB_SHA':'private'}):
            with self.assertRaises(g.GateFailure): g.checked_context({**ENV,**change})
        value=report()
        for sources in ({**value['sources'],'raw_path':'/private/secret'}, {**value['sources'],'script':True}):
            with self.assertRaises(g.GateFailure): g.validate_report({**value,'sources':sources})

    def test_actual_source_hashes_and_copied_path_boundary(self):
        paths=(HERE/'kernel_state_readonly.py',HERE/'recovery_bootargs.py',HERE/'kdp_registry.py')
        self.assertEqual(Path(g.boot.__file__).resolve(),paths[1])
        self.assertEqual(Path(g.boot.kdp_registry.__file__).resolve(),paths[2])
        expected={'script':hashlib.sha256(paths[0].read_bytes()).hexdigest(),
                  'workflow':hashlib.sha256((HERE.parent/'.github/workflows/kernel-state-readonly.yml').read_bytes()).hexdigest(),
                  'bootargs':hashlib.sha256(paths[1].read_bytes()).hexdigest(),
                  'registry':hashlib.sha256(paths[2].read_bytes()).hexdigest()}
        self.assertEqual(g.source_hashes(*paths),expected)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); scripts=root/'scripts'; scripts.mkdir(); workflow=root/'.github/workflows'; workflow.mkdir(parents=True)
            for path in paths: shutil.copy2(path,scripts/path.name)
            shutil.copy2(HERE.parent/'.github/workflows/kernel-state-readonly.yml',workflow/'kernel-state-readonly.yml')
            self.assertEqual(g.source_hashes(*(scripts/path.name for path in paths)),expected)
            with self.assertRaises(g.GateFailure): g.source_hashes(scripts/paths[0].name,paths[1],scripts/paths[2].name)
            (scripts/paths[1].name).unlink(); (scripts/paths[1].name).symlink_to(paths[1])
            with self.assertRaises(g.GateFailure): g.source_hashes(*(scripts/path.name for path in paths))

    def test_kernel_identity_and_filtered_boot_profile_use_fixed_reads(self):
        calls=[]
        def read(argv,limit,timeout):
            calls.append((argv,limit,timeout))
            return (g.KERNEL_UUID+'\n').encode() if argv[0]=='/usr/sbin/sysctl' else ('UUID: '+g.KERNEL_UUID+' (x86_64) /System/Library/Kernels/kernel\n').encode()
        self.assertEqual(g.read_kernel_identity(read),{'live_uuid':g.KERNEL_UUID,'file_uuid':g.KERNEL_UUID})
        self.assertEqual(calls[0][0],['/usr/sbin/sysctl','-n','kern.uuid'])
        self.assertEqual(calls[1][0],['/usr/bin/xcrun','dwarfdump','--uuid','/System/Library/Kernels/kernel'])
        with self.assertRaises(g.GateFailure): g.read_kernel_identity(lambda *a,**k:b'wrong\n')
        profile=g.read_boot_profile(lambda *a,**k:b'private_flag=1 debug=0x102000\n')
        self.assertEqual((profile['status'],profile['debug_mask'],profile['nondebug_token_count']),('observed',0x102000,1))
        self.assertNotIn('private_flag',json.dumps(profile))
        self.assertEqual(g.read_boot_profile(lambda *a,**k:b'debug=1 debug=2\n'),{'status':'invalid'})

    def test_real_cli_rejects_context_and_arm_or_nonroot_before_reading(self):
        command=[sys.executable,str(HERE/'kernel_state_readonly.py')]
        result=subprocess.run(command,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=3)
        self.assertEqual(result.returncode,2); self.assertEqual(result.stdout,'')
        self.assertEqual(result.stderr,'kernel_state_failed invalid_context\n')
        if sys.platform!='darwin' or os.uname().machine!='x86_64' or os.geteuid()!=0:
            result=subprocess.run(command,env={**ENV,'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=3)
            self.assertEqual(result.returncode,2); self.assertEqual(result.stderr,'kernel_state_failed guard_failed\n')

    def test_success_artifact_is_exclusive_readable_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=g.write_report(report(),Path(tmp))
            self.assertEqual(target,Path(tmp).resolve()/'debug/kernel-state-readonly.json')
            self.assertEqual(target.stat().st_mode&0o777,0o644)
            self.assertEqual(json.loads(target.read_text()),report())
            with self.assertRaises(OSError): g.write_report(report(),Path(tmp))
            target.unlink(); target.symlink_to(Path(tmp)/'foreign')
            with self.assertRaises(OSError): g.write_report(report(),Path(tmp))
            self.assertFalse((Path(tmp)/'foreign').exists())

    def test_real_signals_escape_getter_and_reap_current_owned_child(self):
        program=r'''import json,os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]); import kernel_state_readonly as g
prior={number:signal.getsignal(number) for number in (signal.SIGALRM,signal.SIGTERM,signal.SIGINT)}
calls=[]
def read(*args,**kwargs):
 calls.append(1)
 child='import os,time; from pathlib import Path; Path('+repr(sys.argv[2])+').write_text(str(os.getpid())); time.sleep(60)'
 return g.boot.capture([sys.executable,'-c',child],4096,timeout=30,capture_stderr=True)
try:
 with g.signal_guard(): g.read_fields(read=read)
except g.GateFailure as error:
 reason=error.reason
print(json.dumps({'reason':reason,'calls':len(calls),'restored':all(signal.getsignal(n)==v for n,v in prior.items())}),flush=True)
'''
        for number in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM):
            with self.subTest(signal=number),tempfile.TemporaryDirectory() as tmp:
                pidfile=Path(tmp)/'pid'
                controller=subprocess.Popen([sys.executable,'-c',program,str(HERE),str(pidfile)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    deadline=time.monotonic()+3
                    while not pidfile.exists() and time.monotonic()<deadline: time.sleep(.01)
                    self.assertTrue(pidfile.exists())
                    childpid=int(pidfile.read_text()); controller.send_signal(number)
                    out,err=controller.communicate(timeout=4)
                    self.assertEqual((controller.returncode,err),(0,''))
                    self.assertEqual(json.loads(out),{'reason':'deadline' if number==signal.SIGALRM else 'interrupted','calls':1,'restored':True})
                    with self.assertRaises(ProcessLookupError): os.kill(childpid,0)
                finally:
                    if controller.poll() is None: controller.kill(); controller.wait(timeout=2)
                    if pidfile.exists():
                        try: os.kill(int(pidfile.read_text()),signal.SIGKILL)
                        except ProcessLookupError: pass
                    controller.stdout.close(); controller.stderr.close()


if __name__=='__main__': unittest.main()
