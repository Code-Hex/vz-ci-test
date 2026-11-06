import importlib.util
import contextlib
import copy
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("reboot-recovery.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Recovery(unittest.TestCase):
    def test_observed_cli_exposes_entry_and_imports_without_launching_collect_work(self):
        result=subprocess.run(['/bin/sh','-c','exec 3>&1; exec "$1" "$2" collect-observed /invalid BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB',
                               'fixture',r.sys.executable,str(Path(r.__file__).resolve())],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,1)
        self.assertEqual(result.stdout.splitlines(),[b'python_entry',b'imports_done'])

    def test_api_checkpoints_with_a_real_http_exchange(self):
        import http.server
        import threading
        observations=[];received=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PATCH(self):
                received.append(r.json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                raw=b'{"ok":true}'
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*_args):pass
        server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            url='http://127.0.0.1:'+str(server.server_port)+'/checks'
            with patch.object(r,'CHECKS',url):
                result=r.api('PATCH',url,'fixture-token',{'value':'literal'},observe=observations.append)
            self.assertEqual(result,{'ok':True});self.assertEqual(received,[{'value':'literal'}])
            self.assertEqual(observations,['request_ready','opener_ready','response_opened','json_done'])
        finally:server.shutdown();thread.join();server.server_close()

    def test_core_checkpoints_keep_patch_and_get_distinct_after_local_save(self):
        import http.server
        import threading
        config,saved,_=self.followup_fixture();config['context']['after_debug_boot']='begin-nonce-control'
        observations=[];methods=[];check={}
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            outer=self
            class Handler(http.server.BaseHTTPRequestHandler):
                def respond(self):
                    raw=r.json.dumps(check).encode()
                    self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                def do_PATCH(self):
                    methods.append('PATCH')
                    outer.assertTrue((directory/'debug-boot-core.json').exists())
                    data=r.json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    check.update(id=config['check_id'],name='Runner recovery 123',head_sha=config['context']['sha'],
                                 external_id=r.binding(config['context']),app={'id':15368,'slug':'github-actions'},
                                 details_url='https://github.com/Code-Hex/vz-ci-test/runs/'+str(config['check_id']),
                                 status='in_progress',conclusion=None,output=data['output'])
                    self.respond()
                def do_GET(self):methods.append('GET');self.respond()
                def log_message(self,*_args):pass
            server=http.server.HTTPServer(('127.0.0.1',0),Handler)
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:
                with patch.object(r,'CHECKS','http://127.0.0.1:'+str(server.server_port)+'/checks'):
                    facts=r.publish_debug_core(directory,config,saved['scope']['debug_boot_uuid'],saved['facts'],'fixture-token',observe=observations.append)
                self.assertEqual(facts,saved['facts']);self.assertEqual(methods,['PATCH','GET'])
                self.assertEqual(observations,['core_saved','patch_enter','patch_request_ready','patch_opener_ready',
                    'patch_response_opened','patch_json_done','patch_return','get_enter','get_request_ready','get_opener_ready',
                    'get_response_opened','get_json_done','get_return','core_ack'])
            finally:server.shutdown();thread.join();server.server_close()

    def test_begin_control_mode_is_closed_and_never_claims_panic_success(self):
        ctx={'actions':'true','repo':r.REPO,'ref':'refs/heads/main','event':'workflow_dispatch',
             'runner_environment':'github-hosted','run_id':'123','attempt':'1','sha':'a'*40,'trigger':'reboot-quick',
             'debug_boot':True,'debug_source':'bootplist','after_debug_boot':'begin-nonce-control'}
        self.assertTrue(r.valid_context(ctx,'Darwin','x86_64',r.KERNEL_UUID))
        self.assertEqual(r.panic_control_kind(ctx),'dtrace-begin-v1')
        self.assertTrue(r.panic_followup(ctx));self.assertTrue(r.bootmarker_mode(ctx));self.assertTrue(r.kernel_sample_mode(ctx))
        self.assertTrue(r.report_required(ctx));self.assertTrue(r.certificate_required(ctx))
        for change in ({'trigger':'reboot'},{'debug_boot':False},{'debug_source':'nvram'},{'after_debug_boot':'begin-nonce-control-extra'}):
            self.assertFalse(r.valid_context({**ctx,**change},'Darwin','x86_64',r.KERNEL_UUID))
        def forbidden(*a,**kw):self.fail('nonpanic control attempted positive panic classification')
        with patch.object(r.recovery_nvram_panic,'classify_begin',forbidden):
            result=r.classify_followup(b'panic-looking raw',{'context':ctx,'nonce':'b'*64},{},active_bootargs_sha256='c'*64)
        self.assertEqual(result,{'status':'unexpected_reboot','freshness':'unverified','completeness':'unknown','encoding':None})
        self.assertFalse(r.panic_envelope_matches({},'eA==',{},ctx))

    def test_begin_mode_and_trigger_are_closed_without_invented_process_identity(self):
        ctx={'actions':'true','repo':r.REPO,'ref':'refs/heads/main','event':'workflow_dispatch',
             'runner_environment':'github-hosted','run_id':'123','attempt':'1','sha':'a'*40,
             'trigger':'reboot-quick','debug_boot':True,'debug_source':'bootplist','after_debug_boot':'panic-nonce-begin'}
        self.assertTrue(r.valid_context(ctx,'Darwin','x86_64',r.KERNEL_UUID))
        self.assertEqual(r.panic_control_kind(ctx),'dtrace-begin-v1')
        self.assertTrue(r.panic_followup(ctx));self.assertTrue(r.bootmarker_mode(ctx));self.assertTrue(r.kernel_sample_mode(ctx))
        self.assertTrue(r.report_required(ctx));self.assertTrue(r.certificate_required(ctx))
        self.assertEqual(r.expected_debug_mask(ctx),0x102000);self.assertIsNone(r.netdump_mode(ctx))
        self.assertFalse(r.nvram_off_control(ctx))
        scope={'binding':'123/1/'+'a'*40,'nonce':'b'*64,'baseline':'11111111-1111-1111-1111-111111111111',
               'debug_boot_uuid':'22222222-2222-2222-2222-222222222222','source_identity':'c'*64}
        trigger={'scope':scope,'program_sha256':'d'*64,'dtrace_sha256':'e'*64,'prepared':True}
        self.assertTrue(r.panic_trigger_valid(trigger,scope,'dtrace-begin-v1'))
        for change in ({'helper_pid':123},{'tracer_pid':456},{'helper_sha256':'f'*64},{'prepared':1},
                       {'program_sha256':'bad'},{'dtrace_sha256':None},{'scope':{**scope,'nonce':'f'*64}}):
            self.assertFalse(r.panic_trigger_valid({**trigger,**change},scope,'dtrace-begin-v1'))
        for old_kind in ('pid-v1','usdt-v1','reboot-panic-v1'):
            self.assertFalse(r.panic_trigger_valid(trigger,scope,old_kind))
        for change in ({'trigger':'reboot'},{'debug_boot':False},{'debug_source':'nvram'},
                       {'after_debug_boot':'panic-nonce-begin-extra'}):
            self.assertFalse(r.valid_context({**ctx,**change},'Darwin','x86_64',r.KERNEL_UUID))

    def begin_fixture(self, mode='panic-nonce-begin'):
        config,facts,current=self.bootmarker_fixture()
        config['context']['after_debug_boot']=mode;config['cert_fingerprint']='a'*64
        saved={'scope':{**r.debug_boot_marker(config),'debug_boot_uuid':current},'facts':facts}
        n=r.recovery_begin_panic
        prepared={'protocol':n.PROTOCOL,'control_kind':n.KIND,'source_hashes':n.source_hashes(),
            'context_sha256':n.sha(n.canonical(config['context'])),'nonce_sha256':n.sha(config['nonce'].encode()),
            'program_sha256':n.sha(n.program(config['nonce'],context=config['context'])),'dtrace_sha256':'f'*64,'permission_verified':False,
            'build_status':'written','compile_status':'passed','debug_boot_uuid':current,
            'destructive_policy':{'status':'observed','value':0}}
        return config,saved,self.followup_fixture()[2],prepared

    def test_begin_lineage_binds_policy_receipt_marker_source_and_three_boots(self):
        config,saved,b3,prepared=self.begin_fixture();ctx=config['context']
        trigger={'scope':saved['scope'],'program_sha256':prepared['program_sha256'],'dtrace_sha256':prepared['dtrace_sha256'],'prepared':True}
        pending={'nonce':config['nonce'],'baseline_boot_uuid':config['baseline'],'cert_fingerprint':config['cert_fingerprint'],
                 'initial_boot_argument_profile':config['initial_boot_argument_profile']}
        value=r.followup_summary(config,'boot_observed',b3,saved,prepared=prepared,panic_trigger=trigger)
        self.assertTrue(r.boot_proof_matches(value,pending,ctx));self.assertFalse(r.panic_envelope_matches(value,'',pending,ctx))
        for field,replacement in (('control_kind','usdt-v1'),('program_sha256','0'*64),('dtrace_sha256','0'*64),
                                  ('active_bootargs_sha256','0'*64),('after_debug_boot','panic-nonce-usdt'),('prepared',{})):
            self.assertFalse(r.boot_proof_matches({**value,field:replacement},pending,ctx))
        for key,replacement in (('destructive_policy',{'status':'observed','value':False}),('destructive_policy',{'status':'unavailable'}),
                                ('debug_boot_uuid',config['baseline']),('permission_verified',True),('source_hashes',{})):
            bad=copy.deepcopy(value);bad['prepared'][key]=replacement
            self.assertFalse(r.boot_proof_matches(bad,pending,ctx))
        for key in ('kernel_debug_state','boot_marker_control','bootplist_restore','boot_marker_source_identity'):
            bad=copy.deepcopy(value);bad['debug_boot_facts'].pop(key)
            self.assertFalse(r.boot_proof_matches(bad,pending,ctx))
        with self.assertRaises(ValueError):r.runtime_watch_identity(config,saved['scope'],'f'*64)
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);r.private_write(directory/'panic-followup-debug.json',r.json.dumps(saved).encode())
            self.assertEqual(r.read_followup_debug(directory,config),saved)
            bad=copy.deepcopy(saved);bad['facts']['boot_marker_control']={'status':'uncertain'}
            (directory/'panic-followup-debug.json').write_text(r.json.dumps(bad))
            with self.assertRaises(ValueError):r.read_followup_debug(directory,config)

    def test_begin_b3_uses_exact_bootargs_classifier_and_cms_without_fake_pid_or_flags(self):
        for body in ('fresh','missing','wrong_args','wrong_nonce','wrong_program','old_trigger','control_unexpected'):
            with self.subTest(body=body),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);config,saved,b3,prepared=self.begin_fixture('begin-nonce-control' if body=='control_unexpected' else 'panic-nonce-begin');(directory/'panic-control').mkdir()
                trigger={'scope':saved['scope'],'program_sha256':prepared['program_sha256'],'dtrace_sha256':prepared['dtrace_sha256'],'prepared':True}
                if body=='wrong_program':trigger['program_sha256']='0'*64
                if body=='old_trigger':trigger['helper_pid']=123
                for name,value in (('panic-followup-trigger.json',trigger),('panic-control/launch-attempt.json',trigger),
                                   ('panic-control/intent.json',{'scope':saved['scope'],'prepared':prepared})):
                    r.private_write(directory/name,r.json.dumps(value).encode())
                r.private_write(directory/'report-cert.pem',b'certificate boundary')
                args='preempt=10 debug=0x102000 vz_ci_nonce='+('0'*64 if body=='wrong_nonce' else config['nonce'])
                if body=='wrong_args':args=' '+args
                raw=('panic(cpu 0 caller 0x1): dtrace: panic action at probe dtrace:::BEGIN (ecb 0x2)\n'
                     'Kernel UUID: '+r.KERNEL_UUID+'\nBoot args: '+args+'\n').encode() if body!='missing' else None
                completed=[];metadata_seen=[]
                def encrypt(cert,metadata,report):
                    metadata_seen.append(metadata);self.assertEqual(report,raw)
                    self.assertEqual(metadata['after_debug_boot'],config['context']['after_debug_boot']);self.assertEqual(metadata['control_kind'],'dtrace-begin-v1')
                    self.assertEqual(metadata['program_sha256'],prepared['program_sha256']);self.assertEqual(metadata['dtrace_sha256'],prepared['dtrace_sha256'])
                    self.assertEqual(metadata['active_bootargs_sha256'],saved['facts']['boot_marker_control']['active_sha256'])
                    self.assertTrue({'helper_pid','tracer_pid','helper_sha256','flags'}.isdisjoint(metadata))
                    cipher=b'encrypted boundary'
                    return {'ciphertext':r.base64.b64encode(cipher).decode(),'cipher_sha256':r.hashlib.sha256(cipher).hexdigest(),
                            'cert_fingerprint':config['cert_fingerprint']}
                def validate(_d,_n,value,*,context):self.assertEqual(r.recovery_begin_panic.checked_prepared(value,_n,context=context),prepared)
                def forbidden(*a,**kw):self.fail('BEGIN used another control/classifier')
                with patch.object(r.recovery_begin_panic,'validate_prepared',validate), \
                     patch.object(r.recovery_nvram_panic,'classify',forbidden),patch.object(r.recovery_nvram_panic,'classify_usdt',forbidden), \
                     patch.object(r.recovery_nvram_panic,'classify_syscall',forbidden), \
                     patch.object(r.recovery_nvram_panic,'read_panic_info',lambda:('observed' if raw else 'unavailable',raw)), \
                     patch.object(r.recovery_reports,'encrypt_bundle',encrypt), \
                     patch.object(r,'complete_recovery',lambda *_a:completed.append((_a[5],r.json.loads(_a[4]['summary'])))):
                    if body in ('wrong_program','old_trigger'):
                        with self.assertRaises(ValueError):r.followup_finish(directory,config,b3,saved,'token')
                    else:r.followup_finish(directory,config,b3,saved,'token')
                if body in ('wrong_program','old_trigger'):self.assertFalse(completed);self.assertFalse(metadata_seen)
                else:
                    self.assertEqual(completed[0][0],body=='fresh');self.assertEqual(completed[0][1]['prepared'],prepared)
                    self.assertEqual(len(metadata_seen),int(raw is not None))
                    if body=='control_unexpected':
                        self.assertEqual(completed[0][1]['panic_capture']['status'],'unexpected_reboot')
                        self.assertEqual(completed[0][1]['capture_state'],'encrypted_unvalidated')

    def test_begin_followup_gates_single_launch_and_keeps_negative_latch_without_watch(self):
        for case in ('returned','control_returned','mask_zero','marker_invalid','budget','timeout','prepare_fail','policy_bad','boot_bad','ack_fail','trigger_bad','save_started','save_followup'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);config,saved,_b3,prepared=self.begin_fixture('begin-nonce-control' if case=='control_returned' else 'panic-nonce-begin');current=saved['scope']['debug_boot_uuid']
                facts=copy.deepcopy(saved['facts']);calls=[];reports=[];launches=[];reads=[];samples=[];clock=[0]
                facts.pop('kernel_debug_state');facts.pop('optional_inventory_status')
                if case=='marker_invalid':facts['boot_marker_control']={'status':'invalid'}
                if case=='policy_bad':prepared['destructive_policy']['value']=False
                if case=='boot_bad':prepared['debug_boot_uuid']=config['baseline']
                trigger={'scope':saved['scope'],'program_sha256':prepared['program_sha256'],'dtrace_sha256':prepared['dtrace_sha256'],'prepared':True}
                if case=='trigger_bad':trigger['helper_pid']=123
                write=r.private_write
                def save(path,raw):
                    if (case=='save_started' and path.name=='debug-boot-inventory-started.json' or
                            case=='save_followup' and path.name=='panic-followup-debug.json'):raise OSError('private save failed')
                    write(path,raw)
                def read(argv,limit,**kw):
                    if argv[0]=='/usr/bin/sample':samples.append(argv);return b'private stack'
                    reads.append(argv);self.assertEqual(kw['timeout'],30)
                    if case=='timeout':
                        kw['on_timeout'](123,{'timeout_seconds':30,'stdout':b'','stderr':b''})
                        raise subprocess.TimeoutExpired(argv,30,output=b'',stderr=b'')
                    return ('VZKSTATE v1 debug_boot_arg u32 '+('0' if case=='mask_zero' else str(0x102000))+'\n\n').encode()
                def prepare(_d,nonce,_save,_sync,*,context,deadline):
                    calls.append('prepare');self.assertEqual(context,config['context']);self.assertEqual(deadline,180)
                    if case=='prepare_fail':raise ValueError('private policy or compile failed')
                    return prepared
                def publish(_d,_c,_t,value,title):
                    calls.append(value['phase']);self.assertEqual(value['control_kind'],'dtrace-begin-v1')
                    self.assertNotIn('helper_pid',value);self.assertNotIn('flags',value)
                    if case=='ack_fail' and value['phase']=='panic_intent':raise OSError('private ACK failure')
                def fire(_d,scope,value,_save,_sync,on_ready,current_boot_uuid,*,context,deadline):
                    calls.append('fire');self.assertEqual(scope,saved['scope']);self.assertEqual(deadline,180)
                    if on_ready(trigger):launches.append(True)
                    return {'phase':'returned','launch_status':'launched','dtrace_exit':70,'outcome':'control' if case=='control_returned' else 'after_action',
                            'fault_code':None,'output_complete':True,'output_overflow':False,'ownership_faults':0}
                def forbidden(*a,**kw):self.fail('BEGIN touched legacy Watch/fire/profile path')
                with contextlib.ExitStack() as stack:
                    for owner,name,value in ((r,'boot_uuid',lambda:current),(r.time,'monotonic',lambda:clock[0]),
                        (r,'private_write',save),(r.recovery_bootargs,'capture',read),(r.recovery_begin_panic,'prepare',prepare),
                        (r.recovery_begin_panic,'fire',fire),(r,'publish_followup',publish),
                        (r,'complete_recovery',lambda _d,_c,_b,_t,o,ok,d:reports.append((o,ok,d))),
                        (r,'start_runtime_watch',forbidden),(r,'runtime_watch_alive',forbidden),
                        (r.recovery_panic_control,'prepare',forbidden),(r.recovery_panic_control,'fire',forbidden),
                        (r.recovery_reboot_panic,'prepare',forbidden),(r.recovery_reboot_panic,'fire',forbidden),
                        (r,'postboot_argument_profiles',forbidden),(r,'postboot_paniclog_control',forbidden)):
                        stack.enter_context(patch.object(owner,name,value))
                    if case=='budget':clock[0]=140
                    r.followup_start(directory,config,current,facts,'token',deadline=180)
                    if case!='save_followup':
                        with patch.object(r,'load_config',lambda _:config),patch.object(r.recovery_bootplist,'finish',forbidden):
                            r.collect(directory)
                self.assertEqual(launches,[True] if case in ('returned','control_returned') else [])
                self.assertEqual(len(reports),1);self.assertFalse(reports[0][1]);self.assertEqual(reports[0][2],clock[0]+60)
                self.assertEqual('prepare' in calls,case in ('returned','control_returned','prepare_fail','policy_bad','boot_bad','ack_fail','trigger_bad'))
                self.assertEqual(len(reads),0 if case in ('budget','save_started') else 1)
                self.assertEqual(len(samples),int(case=='timeout'))
                self.assertEqual((directory/'panic-followup-debug.json').exists(),case!='save_followup')
                if case in ('returned','control_returned'):self.assertEqual(calls,['prepare','panic_prepared','fire','panic_intent'])
                if case=='control_returned':
                    data=r.json.loads(reports[0][0]['summary'])
                    self.assertEqual(data['after_debug_boot'],'begin-nonce-control')
                    self.assertEqual(data['panic_control']['result']['outcome'],'control')

    def test_begin_restore_failure_retries_only_restore_before_core_latch_return(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);config,saved,_b3,_prepared=self.begin_fixture();current=saved['scope']['debug_boot_uuid'];finishes=[]
            r.private_write(directory/'token',b'token')
            r.private_write(directory/'ready.json',r.json.dumps({'baseline':config['baseline'],'nonce':config['nonce'],'preboot_patch':True}).encode())
            def finish(*a,**kw):
                finishes.append(True);value=copy.deepcopy(saved['facts'])
                if len(finishes)==1:value['bootplist_restored']=False
                return value
            def core(_d,_c,_b,value,_t):
                r.private_write(directory/'debug-boot-core.json',r.json.dumps({'facts':value}).encode());return value
            def forbidden(*a,**kw):self.fail('failed restore reached observation or launch')
            with patch.object(r,'load_config',lambda _:config),patch.object(r,'boot_uuid',lambda:current), \
                 patch.object(r.recovery_bootplist,'finish',finish),patch.object(r,'publish_debug_core',core), \
                 patch.object(r.recovery_bootargs,'capture',forbidden),patch.object(r.recovery_begin_panic,'prepare',forbidden), \
                 patch.object(r.recovery_begin_panic,'fire',forbidden),patch.object(r,'postboot_argument_profiles',forbidden), \
                 patch.object(r,'postboot_paniclog_control',forbidden):
                with self.assertRaises(ValueError):r.collect(directory)
                self.assertFalse((directory/'panic-followup-debug.json').exists())
                r.collect(directory)
            self.assertEqual(len(finishes),2);self.assertFalse((directory/'panic-control'/'launch-attempt.json').exists())

    def test_begin_controller_pins_b1_profile_and_requires_b3_receipt_and_body(self):
        for case in ('fresh','missing_baseline','changed_b1','policy','marker','missing_body','program','control_false_success'):
            with self.subTest(case=case):
                config,saved,b3,prepared=self.begin_fixture('begin-nonce-control' if case=='control_false_success' else 'panic-nonce-begin');ctx=config['context'];cipher=b'encrypted boundary'
                trigger={'scope':saved['scope'],'program_sha256':prepared['program_sha256'],'dtrace_sha256':prepared['dtrace_sha256'],'prepared':True}
                public={'protocol':'vz-recovery-v1','phase':'public_key','binding':r.binding(ctx),'nonce':config['nonce'],
                    'baseline_boot_uuid':config['baseline'],'public_key':'public','cert_fingerprint':config['cert_fingerprint'],
                    'debug_boot':True,'debug_source':'bootplist','after_debug_boot':ctx['after_debug_boot'],'trigger':'reboot-quick',
                    'initial_boot_argument_profile':config['initial_boot_argument_profile']}
                if case=='missing_baseline':public.pop('initial_boot_argument_profile')
                final=r.followup_summary(config,'boot_observed',b3,saved,prepared=prepared,panic_trigger=trigger,
                    capture_state='fresh_fragment',panic_capture={'status':'fresh_fragment','freshness':'verified','completeness':'unknown','encoding':'raw'},
                    cipher_sha256=r.hashlib.sha256(cipher).hexdigest())
                if case=='policy':final['prepared']['destructive_policy']={'status':'observed','value':False}
                if case=='marker':final['debug_boot_facts']['boot_marker_control']={'status':'unavailable'}
                if case=='program':final['program_sha256']='0'*64
                if case=='missing_body':final['capture_state']='unavailable'
                sequence=[{'id':9,'status':'in_progress','output':{'summary':r.json.dumps(public)}}]
                if case=='changed_b1':sequence.append({'id':9,'status':'in_progress','output':{'summary':r.json.dumps({**public,
                    'initial_boot_argument_profile':r.recovery_bootargs.boot_argument_profile(b'foreign=1')})}})
                sequence.append({'id':9,'status':'completed','conclusion':'success','output':{'summary':r.json.dumps(final),
                    'text':r.base64.b64encode(cipher).decode() if case!='missing_body' else ''}})
                checks=iter(sequence);writes=[]
                def api(method,url,token,payload=None,**kw):
                    if method=='GET':return {'status':'completed'}
                    writes.append(payload);return {}
                with patch.object(r,'list_check',lambda *_:next(checks)),patch.object(r,'api',api), \
                     patch.object(r,'encrypt_token',lambda *_:b'sealed'),patch.object(r.time,'sleep',lambda _:None), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if case=='fresh':r.controller(ctx,'token')
                    else:
                        with self.assertRaises(ValueError):r.controller(ctx,'token')
                self.assertEqual(len(writes),0 if case=='missing_baseline' else 1)

    def test_begin_negative_latch_checks_scope_and_never_retries_or_weakens_launched_proof(self):
        for case in ('same_b2','later_boot','foreign_scope','extra_key','launched'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);config,saved,b3,_prepared=self.begin_fixture()
                current=b3 if case=='later_boot' else saved['scope']['debug_boot_uuid']
                saved['facts']['kernel_debug_state']={'debug_boot_arg':{'status':'unavailable'}}
                if case=='foreign_scope':saved['scope']['source_identity']='0'*64
                if case=='extra_key':saved['extra']=True
                r.private_write(directory/'panic-followup-debug.json',r.json.dumps(saved).encode())
                if case=='launched':
                    (directory/'panic-control').mkdir();r.private_write(directory/'panic-control'/'launch-attempt.json',b'{}')
                def forbidden(*a,**kw):self.fail('BEGIN negative latch retried an operation')
                with patch.object(r,'load_config',lambda _:config),patch.object(r,'boot_uuid',lambda:current), \
                     patch.object(r.recovery_bootplist,'finish',forbidden),patch.object(r.recovery_bootargs,'capture',forbidden), \
                     patch.object(r.recovery_begin_panic,'prepare',forbidden),patch.object(r.recovery_begin_panic,'fire',forbidden), \
                     patch.object(r,'followup_finish',forbidden):
                    if case in ('same_b2','later_boot'):r.collect(directory)
                    else:
                        with self.assertRaises(ValueError):r.collect(directory)

    def test_reader_sample_mode_is_closed_nonpanic_and_requires_only_transport_cert(self):
        config, _facts, _current = self.bootmarker_fixture()
        ctx = {**config['context'], 'after_debug_boot':'bootargs-marker-sample'}
        self.assertTrue(r.valid_context(ctx,'Darwin','x86_64',r.KERNEL_UUID))
        self.assertTrue(r.bootmarker_mode(ctx)); self.assertTrue(r.certificate_required(ctx))
        self.assertFalse(r.panic_followup(ctx)); self.assertFalse(r.report_required(ctx)); self.assertFalse(r.panic_mode(ctx))
        self.assertEqual(r.expected_debug_mask(ctx),0x102000);self.assertIsNone(r.netdump_mode(ctx))
        for change in ({'trigger':'reboot'},{'debug_boot':False},{'debug_source':'nvram'},{'after_debug_boot':'bootargs-marker-sample-extra'}):
            self.assertFalse(r.valid_context({**ctx,**change},'Darwin','x86_64',r.KERNEL_UUID))
        self.assertFalse(r.certificate_required(config['context']))

    def test_reader_sample_publication_is_bounded_separate_and_canonical(self):
        for case in ('success','budget','crypto','post','get','wrong_app','wrong_text','wrong_id','wrong_origin'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);config,facts,current=self.bootmarker_fixture()
                config['context']['after_debug_boot']='bootargs-marker-sample';config['cert_fingerprint']='a'*64
                scope={**r.debug_boot_marker(config),'debug_boot_uuid':current}
                sampler=r.recovery_kernel_sample.Sampler(scope,deadline=r.time.monotonic()+180,
                    read=lambda *a,**kw:b'private stack fragment')
                sampler(123,{'timeout_seconds':30,'stdout':b'','stderr':b''})
                facts['kernel_debug_state']={'debug_boot_arg':{'status':'unavailable',
                    'error':r.recovery_bootargs.kernel_failure('timeout',subprocess.TimeoutExpired('owned',30,output=b'',stderr=b''))}}
                if case=='wrong_origin': facts['kernel_debug_state']['debug_boot_arg']['error']['output_bytes']=1
                r.private_write(directory/'report-cert.pem',b'certificate boundary')
                calls=[];encrypted=[];canonical={}
                def encrypt(cert,metadata,raw):
                    encrypted.append((metadata,raw));self.assertEqual(cert,b'certificate boundary')
                    self.assertEqual(metadata['scope'],scope)
                    payload=r.json.loads(raw);self.assertEqual(r.base64.b64decode(payload['stdout']),b'private stack fragment')
                    self.assertEqual(r.base64.b64decode(payload['stderr']),b'')
                    if case=='crypto': raise ValueError('private failure text')
                    return {'cert_fingerprint':'a'*64,'cipher_sha256':'b'*64,'ciphertext':'CMS_ONLY'}
                def api(method,url,token,payload=None,**kwargs):
                    calls.append(method);self.assertEqual(token,'token')
                    self.assertNotIn('private stack fragment',r.json.dumps(payload))
                    if method=='POST':
                        if case=='post': raise OSError('private API failure')
                        canonical.update(payload);canonical.update(id=99,app={'id':15368,'slug':'github-actions'})
                        return copy.deepcopy(canonical)
                    if case=='get': raise OSError('private GET failure')
                    value=copy.deepcopy(canonical)
                    if case=='wrong_app':value['app']['id']=1
                    if case=='wrong_text':value['output']['text']='changed'
                    if case=='wrong_id':value['id']=True
                    return value
                before=copy.deepcopy(facts)
                with patch.object(r.recovery_reports,'encrypt_bundle',encrypt),patch.object(r,'api',api):
                    result=r.publish_kernel_sample(directory,config,current,sampler,facts,'token',
                        r.time.monotonic()+(99 if case=='budget' else 180))
                self.assertEqual(facts,before)
                self.assertEqual(result['publication'],'acknowledged' if case=='success' else 'no_budget' if case=='budget' else 'failed')
                self.assertEqual(result['check_id'],99 if case in ('success','get','wrong_app','wrong_text','wrong_id') else None)
                self.assertEqual(len(encrypted),0 if case in ('budget','wrong_origin') else 1)
                if case=='success':
                    self.assertEqual(calls,['POST','GET']);self.assertEqual(canonical['conclusion'],'neutral')
                    self.assertEqual(canonical['output']['text'],'CMS_ONLY')
                    self.assertTrue(canonical['external_id'].startswith(r.binding(config['context'])+'/reader-sample/'))
                    self.assertEqual(r.json.loads(canonical['output']['summary'])['sample'],sampler.public_fact())

    def test_reader_sample_collect_preserves_primary_outcome_cleanup_order_and_once(self):
        for case in ('observed','timeout','late_value','observer_error','budget','crypto','post','no_publish_budget','restore_failed'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);config,facts,current=self.bootmarker_fixture()
                config['context']['after_debug_boot']='bootargs-marker-sample';config['cert_fingerprint']='a'*64
                facts.pop('optional_inventory_status');facts.pop('kernel_debug_state')
                if case=='restore_failed':facts['bootplist_restored']=False
                for name,data in (('token',b'token'),('report-cert.pem',b'certificate boundary'),
                    ('ready.json',r.json.dumps({'baseline':config['baseline'],'nonce':config['nonce'],'preboot_patch':True}).encode())):
                    r.private_write(directory/name,data)
                clock=[0];reads=[];samples=[];reports=[];calls=[];encrypted=[];reaped=[];checks={}
                def core(_d,_c,_b,value,_t):
                    path=directory/'debug-boot-core.json'
                    if not path.exists():r.private_write(path,r.json.dumps({'facts':value}).encode())
                    if case=='budget':clock[0]=140
                    return r.json.loads(path.read_text())['facts']
                def read(argv,limit,**options):
                    if argv[0]=='/usr/bin/sample':
                        self.assertFalse(reaped);samples.append(argv)
                        if case=='observer_error':raise OSError('owned observer failed')
                        return b'private native stack prefix'
                    reads.append(argv)
                    self.assertEqual(options['timeout'],30);self.assertIn('on_timeout',options)
                    if case=='observed':return b'VZKSTATE v1 debug_boot_arg u32 1056768\n\n'
                    if case=='no_publish_budget':clock[0]=90
                    options['on_timeout'](123,{'timeout_seconds':30,'stdout':b'','stderr':b''})
                    # The capture owner has frozen timeout before an optional late return and reaped before returning.
                    if case=='late_value': self.assertFalse(reaped)
                    reaped.append(True)
                    raise subprocess.TimeoutExpired(argv,30,output=b'',stderr=b'')
                def encrypt(cert,metadata,raw):
                    self.assertEqual(reaped,[True]);encrypted.append(raw)
                    if case=='crypto':raise ValueError('private crypto failure')
                    return {'cert_fingerprint':'a'*64,'cipher_sha256':'b'*64,'ciphertext':'CMS_ONLY'}
                def api(method,url,token,payload=None,**options):
                    self.assertEqual(reaped,[True]);calls.append(method)
                    if case=='post':raise OSError('private API failure')
                    if method=='POST':checks.update(payload,id=99,app={'id':15368,'slug':'github-actions'})
                    return copy.deepcopy(checks)
                def forbidden(*a,**kw):self.fail('nonfaulting sample mode entered a panic or full inventory path')
                with contextlib.ExitStack() as stack:
                    for owner,name,value in ((r,'load_config',lambda _:config),(r,'boot_uuid',lambda:current),
                        (r.recovery_bootplist,'finish',lambda *a,**kw:copy.deepcopy(facts)),(r,'publish_debug_core',core),
                        (r.recovery_bootargs,'capture',read),(r.recovery_reports,'encrypt_bundle',encrypt),(r,'api',api),
                        (r,'complete_recovery',lambda _d,_c,_b,_t,o,s,d:reports.append((o,s,d))),
                        (r.time,'monotonic',lambda:clock[0]),(r,'followup_start',forbidden),(r,'start_runtime_watch',forbidden),
                        (r.recovery_bootargs.MacPlatform,'inventory',forbidden),(r.recovery_panic_control,'build',forbidden),
                        (r.recovery_panic_control,'prepare',forbidden),(r.recovery_panic_control,'fire',forbidden)):
                        stack.enter_context(patch.object(owner,name,value))
                    r.collect(directory);r.collect(directory)
                self.assertEqual(len(reports),1);output,success,deadline=reports[0]
                self.assertEqual(success,case=='observed');self.assertEqual(deadline,180)
                summary=r.json.loads(output['summary']);self.assertEqual(summary['capture_state'],'boot_only');self.assertNotIn('text',output)
                self.assertEqual(len(reads),0 if case in ('budget','restore_failed') else 1)
                self.assertEqual(len(samples),0 if case in ('observed','budget','restore_failed') else 1)
                actual=summary['debug_boot_facts']
                if case not in ('observed','budget','restore_failed'):
                    self.assertEqual(actual['kernel_debug_state']['debug_boot_arg']['error']['reason'],'timeout')
                    publication=actual['kernel_reader_sample']['publication']
                    self.assertEqual(publication,'no_budget' if case=='no_publish_budget' else 'failed' if case in ('crypto','post') else 'acknowledged')
                if case in ('observed','budget','restore_failed','no_publish_budget'):self.assertFalse(encrypted);self.assertFalse(calls)

    def test_reader_sample_maximum_prefix_is_encrypted_and_decrypts_with_exact_scope(self):
        import gzip
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);config,facts,current=self.bootmarker_fixture()
            config['context']['after_debug_boot']='bootargs-marker-sample'
            key=directory/'recipient.key';cert=directory/'report-cert.pem'
            subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:4096','-nodes',
                '-keyout',str(key),'-out',str(cert),'-subj','/CN=local-test','-days','1'],
                check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            config['cert_fingerprint']=r.recovery_reports.cert_fingerprint(cert.read_bytes())
            scope={**r.debug_boot_marker(config),'debug_boot_uuid':current}
            out=os.urandom(22528);err=os.urandom(2048)
            def read(*a,**kw):raise subprocess.CalledProcessError(1,'sample',output=out,stderr=err)
            sampler=r.recovery_kernel_sample.Sampler(scope,deadline=r.time.monotonic()+180,read=read)
            sampler(123,{'timeout_seconds':30,'stdout':b'','stderr':b''})
            facts['kernel_debug_state']={'debug_boot_arg':{'status':'unavailable','error':
                r.recovery_bootargs.kernel_failure('timeout',subprocess.TimeoutExpired('owned',30,output=b'',stderr=b''))}}
            check={}
            def api(method,url,token,payload=None,**kw):
                if method=='POST':check.update(payload,id=99,app={'id':15368,'slug':'github-actions'})
                return copy.deepcopy(check)
            with patch.object(r,'api',api):
                result=r.publish_kernel_sample(directory,config,current,sampler,facts,'token',r.time.monotonic()+180)
            self.assertEqual(result['publication'],'acknowledged')
            encoded=check['output']['text'];self.assertLessEqual(len(encoded),58000)
            encrypted=r.base64.b64decode(encoded,validate=True)
            summary=r.json.loads(check['output']['summary'])
            self.assertEqual(summary['cipher_sha256'],r.hashlib.sha256(encrypted).hexdigest())
            compressed=subprocess.run(['/usr/bin/openssl','cms','-decrypt','-inform','DER','-binary',
                '-recip',str(cert),'-inkey',str(key)],input=encrypted,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,check=True,timeout=10).stdout
            bundle=r.json.loads(gzip.decompress(compressed));raw=r.base64.b64decode(bundle['report_base64'])
            self.assertEqual(bundle['metadata']['scope'],scope);self.assertEqual(bundle['metadata']['sample'],sampler.public_fact())
            self.assertEqual(bundle['report_sha256'],r.hashlib.sha256(raw).hexdigest())
            fragments=r.json.loads(raw)
            self.assertEqual(r.base64.b64decode(fragments['stdout']),out)
            self.assertEqual(r.base64.b64decode(fragments['stderr']),err)

    def test_bootmarker_mode_is_nonfaulting_and_closed(self):
        config, _saved, _b3 = self.syscall_fixture()
        ctx = {**config['context'], 'after_debug_boot': 'bootargs-marker'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertEqual(r.expected_debug_mask(ctx), 0x102000)
        self.assertFalse(r.panic_followup(ctx)); self.assertFalse(r.panic_mode(ctx))
        self.assertFalse(r.report_required(ctx)); self.assertFalse(r.certificate_required(ctx))
        self.assertFalse(r.kernel_state_mode(ctx)); self.assertIsNone(r.netdump_mode(ctx))
        for change in ({'trigger':'reboot'}, {'debug_source':'nvram'}, {'debug_boot':False},
                       {'after_debug_boot':'bootargs-marker-extra'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))

    def bootmarker_fixture(self):
        config, saved, _ = self.syscall_fixture()
        config['context']['after_debug_boot'] = 'bootargs-marker'
        config['cert_fingerprint'] = ''
        config['check_id'] = 9
        config['debug_boot'] = True
        baseline = r.recovery_bootargs.boot_argument_profile(b'preempt=10')
        config['initial_boot_argument_profile'] = baseline
        token = 'vz_ci_nonce=' + config['nonce']
        raw = ('preempt=10 debug=0x102000 ' + token).encode()
        control = {'status':'observed', 'marker_sha256':r.hashlib.sha256(token.encode()).hexdigest(),
                   'active_sha256':r.hashlib.sha256(raw).hexdigest(), 'active_byte_count':len(raw),
                   'full_profile':r.recovery_bootargs.boot_argument_profile(raw),
                   'remaining_profile':r.recovery_bootargs.boot_argument_profile(b'preempt=10 debug=0x102000')}
        facts = {**saved['facts'], 'boot_marker_control':control,
                 'boot_marker_source_identity':r.debug_source_identity()}
        return config, facts, saved['scope']['debug_boot_uuid']

    def test_bootmarker_controller_requires_independent_baseline_and_all_proofs(self):
        config, facts, current = self.bootmarker_fixture(); ctx = config['context']
        pending = {'nonce':config['nonce'], 'baseline_boot_uuid':config['baseline'], 'cert_fingerprint':'',
                   'initial_boot_argument_profile':config['initial_boot_argument_profile']}
        data = {'protocol':'vz-recovery-v1','phase':'boot_observed','binding':r.binding(ctx),
                'nonce':config['nonce'],'baseline_boot_uuid':config['baseline'],'current_boot_uuid':current,
                'trigger':'reboot-quick','debug_boot':True,'debug_source':'bootplist',
                'after_debug_boot':'bootargs-marker','cert_fingerprint':'','debug_boot_facts':facts,'capture_state':'boot_only'}
        self.assertTrue(r.boot_proof_matches(data,pending,ctx))
        self.assertFalse(r.panic_envelope_matches(data,'',pending,ctx))
        for change in ({'boot_marker_control':{'status':'invalid'}}, {'boot_marker_control':{'status':'uncertain'}},
                       {'boot_marker_control':{**facts['boot_marker_control'],'extra':1}},
                       {'boot_marker_control':{**facts['boot_marker_control'],'active_byte_count':True}},
                       {'boot_marker_source_identity':'0'*64}, {'bootplist_restored':False},
                       {'bootplist_restore':{**facts['bootplist_restore'],'data':{'bytes':1,'metadata':True,'timestamps':True}}},
                       {'kernel_debug_state':{'debug_boot_arg':{'status':'observed','value':0}}},
                       {'optional_inventory_status':'uncertain'}):
            self.assertFalse(r.boot_proof_matches({**data,'debug_boot_facts':{**facts,**change}},pending,ctx))
        for changed in ({k:v for k,v in pending.items() if k!='initial_boot_argument_profile'},
                        {**pending,'initial_boot_argument_profile':r.recovery_bootargs.boot_argument_profile(b'foreign=1')},
                        {**pending,'nonce':'b'*64}):
            self.assertFalse(r.boot_proof_matches(data,changed,ctx))
        self.assertFalse(r.boot_proof_matches(data,pending,{**ctx,'after_debug_boot':'kernel-state'}))
        armed = {**data, 'phase':'armed', 'initial_boot_argument_profile':pending['initial_boot_argument_profile']}
        self.assertTrue(r.armed_matches(armed,pending,ctx))
        self.assertFalse(r.armed_matches({**armed,'initial_boot_argument_profile':{'status':'unavailable'}},pending,ctx))

    def test_bootmarker_baseline_uses_one_strict_read_and_rejects_invalid(self):
        ctx = {'after_debug_boot':'bootargs-marker'}; calls=[]
        def read(argv, limit, **kwargs):
            calls.append((argv,limit,kwargs)); return b'preempt=10\n'
        def forbidden(*args,**kwargs): self.fail('legacy profile read used')
        with patch.object(r.recovery_bootargs,'capture',read), patch.object(r,'observe_boot_argument_profile',forbidden):
            self.assertEqual(r.observe_initial_boot_arguments(ctx),r.recovery_bootargs.boot_argument_profile(b'preempt=10'))
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][0],['/usr/sbin/sysctl','-n','kern.bootargs'])
        for raw in (b'preempt=10',b'preempt=10\n\n',b'preempt=10\r\n',b'debug=0x2000\n',b'vz_ci_nonce='+b'a'*64+b'\n'):
            with patch.object(r.recovery_bootargs,'capture',lambda *args,**kwargs:raw):
                with self.assertRaises(ValueError): r.observe_initial_boot_arguments(ctx)

    def test_bootmarker_collect_observes_only_critical_once_and_never_fires(self):
        for case in ('positive','mask_zero','marker_invalid','restore_failed','finish_error','budget','save_started','save_result','sync_result','restore_recovers','completion_save'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);config,facts,current=self.bootmarker_fixture(); reads=[];reports=[];finishes=[];completion_patches=[]
                facts.pop('optional_inventory_status',None);facts.pop('kernel_debug_state',None)
                if case=='marker_invalid': facts['boot_marker_control']={'status':'invalid'}
                if case=='restore_failed': facts['bootplist_restored']=False
                r.private_write(directory/'token',b'token')
                r.private_write(directory/'ready.json',r.json.dumps({'baseline':config['baseline'],'nonce':config['nonce'],'preboot_patch':True}).encode())
                original_write=r.private_write; original_sync=r.sync_directory; save_errors=[]; sync_errors=[]
                def save(path,data):
                    if not save_errors and (case=='save_started' and path.name=='debug-boot-inventory-started.json' or
                        case=='save_result' and path.name=='debug-boot-inventory-result.json'):
                        save_errors.append(path.name)
                        raise OSError('synthetic persistence failure')
                    original_write(path,data)
                def sync(path):
                    if case=='sync_result' and not sync_errors and (directory/'debug-boot-inventory-result.json').exists():
                        sync_errors.append(True)
                        raise OSError('synthetic result sync failure')
                    original_sync(path)
                def finish(*args,**kwargs):
                    finishes.append(True)
                    if case=='finish_error' and len(finishes)==1: raise OSError('synthetic finish unavailable')
                    self.assertEqual(kwargs['baseline_boot_argument_profile'],config['initial_boot_argument_profile'])
                    value=copy.deepcopy(facts)
                    if case=='restore_recovers' and len(finishes)==1: value['bootplist_restored']=False
                    return value
                def core(_d,_c,_b,value,_t):
                    path=directory/'debug-boot-core.json'
                    if not path.exists(): original_write(path,r.json.dumps({'facts':value}).encode())
                    return r.json.loads(path.read_text())['facts']
                def read(argv,limit,**kwargs):
                    self.assertEqual(argv,['/usr/sbin/dtrace','-q','-x','errtags','-n',r.recovery_bootargs.kernel_field_program('debug_boot_arg')])
                    self.assertEqual(kwargs,{'timeout':30,'capture_stderr':True});reads.append(argv)
                    return ('VZKSTATE v1 debug_boot_arg u32 '+('0' if case=='mask_zero' else str(0x102000))+'\n\n').encode()
                def forbidden(*args,**kwargs): self.fail('nonfaulting marker mode entered a panic or full inventory path')
                original_complete=r.complete_recovery
                def complete(_d,_c,_b,_t,output,successful,deadline):
                    reports.append((output,successful,deadline))
                    if case=='completion_save':
                        expired=[]
                        def completion_write(path,data):
                            if path.name=='completed.json':
                                expired.append(True)
                                raise OSError('synthetic completion persistence failure')
                            original_write(path,data)
                        def completed_patch(method,_url,_token,payload,**kwargs):
                            self.assertEqual(method,'PATCH');completion_patches.append(payload['conclusion'])
                            return {}
                        with patch.object(r,'api',completed_patch),patch.object(r,'private_write',completion_write), \
                             patch.object(r.time,'monotonic',lambda:deadline+1 if expired else deadline-1), \
                             patch.object(r.time,'sleep',lambda _:None):
                            original_complete(_d,_c,_b,_t,output,successful,deadline)
                # One clock value for the collect deadline, then an exhausted budget at the read boundary.
                times=iter((100,260,400,560))
                with contextlib.ExitStack() as stack:
                    for owner,name,value in ((r,'load_config',lambda _:config),(r,'boot_uuid',lambda:current),
                        (r.recovery_bootplist,'finish',finish),(r,'publish_debug_core',core),(r,'private_write',save),
                        (r.recovery_bootargs,'capture',read),(r,'complete_recovery',complete),(r,'sync_directory',sync),
                        (r,'followup_start',forbidden),(r,'start_runtime_watch',forbidden),
                        (r,'postboot_argument_profiles',forbidden),(r.recovery_bootargs.MacPlatform,'inventory',forbidden),
                        (r.recovery_panic_control,'build',forbidden),(r.recovery_panic_control,'prepare',forbidden),
                        (r.recovery_panic_control,'fire',forbidden),(r.recovery_reboot_panic,'build',forbidden),
                        (r.recovery_reboot_panic,'prepare',forbidden),(r.recovery_reboot_panic,'fire',forbidden)):
                        stack.enter_context(patch.object(owner,name,value))
                    if case=='budget': stack.enter_context(patch.object(r.time,'monotonic',lambda:next(times)))
                    r.collect(directory)
                    first_reads=len(reads)
                    r.collect(directory)
                self.assertEqual(len(reads),first_reads)
                self.assertEqual(first_reads,0 if case in ('restore_failed','restore_recovers','finish_error','budget','save_started') else 1)
                self.assertEqual([item[1] for item in reports],[case in ('positive','completion_save')])
                self.assertEqual(len(finishes),2)
                self.assertEqual(completion_patches,['success'] if case=='completion_save' else [])
                for output,_successful,_deadline in reports:
                    data=r.json.loads(output['summary'])
                    self.assertEqual(data['capture_state'],'boot_only');self.assertNotIn('text',output)
                    self.assertNotIn('panic_trigger',data)
                    if case=='finish_error': self.assertEqual(data['debug_boot_facts']['boot_marker_control'],{'status':'unavailable'})
                    self.assertEqual(output['title'],'Boot marker confirmed' if case in ('positive','completion_save') else 'Boot marker not confirmed')
                if case=='budget': self.assertEqual(reports[0][2],280)

    def test_bootmarker_b1_preparation_and_arming_preserve_baseline_without_panic_build(self):
        self.assert_bootmarker_b1_preparation(False)

    def test_reader_sample_b1_requires_transport_certificate_without_panic_build(self):
        self.assert_bootmarker_b1_preparation(True)

    def test_begin_b1_builds_only_program_and_preserves_owned_marker_baseline(self):
        self.assert_bootmarker_b1_preparation(True, begin=True)

    def assert_bootmarker_b1_preparation(self, sample, begin=False):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);directory=parent/'recovery';config,_facts,_current=self.bootmarker_fixture()
            if sample: config['context']['after_debug_boot']='panic-nonce-begin' if begin else 'bootargs-marker-sample'
            helper=parent/'recovery-quick-reboot';helper.write_bytes(b'never executed')
            outputs=[];reads=[]
            def api(method,_url,_token,payload=None,**kwargs):
                self.assertIn(method,('POST','PATCH'));outputs.append(r.json.loads(payload['output']['summary']))
                return {'id':9}
            def read(argv,limit,**kwargs):
                self.assertEqual(argv,['/usr/sbin/sysctl','-n','kern.bootargs']);reads.append(argv)
                return b'preempt=10\n'
            def forbidden(*args,**kwargs): self.fail('nonfaulting preparation entered panic path')
            def encrypt(cert,metadata,raw):
                self.assertTrue(sample);self.assertEqual(cert,b'certificate boundary')
                self.assertEqual(metadata,{'preflight':True});self.assertEqual(raw,b'synthetic')
                return {'cert_fingerprint':'a'*64}
            with contextlib.ExitStack() as stack,contextlib.redirect_stdout(io.StringIO()):
                for owner,name,value in ((r,'root_only',lambda:None),(r,'require_context',lambda *_:None),
                    (r,'root_dir',lambda _:directory),(r,'boot_uuid',lambda:config['baseline']),
                    (r,'api',api),(r,'diagnostic_sysctls',lambda:{}),(r.recovery_bootargs,'capture',read),
                    (r.recovery_panic_control,'build',forbidden),(r.recovery_reboot_panic,'build',forbidden),
                    (r.recovery_nvram_panic,'read_panic_info',(lambda:('unavailable',None)) if begin else forbidden),
                    (r.recovery_reports,'encrypt_bundle',encrypt if sample else forbidden)):
                    stack.enter_context(patch.object(owner,name,value))
                if begin:stack.enter_context(patch.object(r.recovery_begin_panic,'_tool_sha',lambda:'f'*64))
                r.prepare_root({'context':config['context'],'token':'token','quick_helper':str(helper),'report_cert':'certificate boundary' if sample else 'ignored'})
                actual=r.json.loads((directory/'config.json').read_text())
                self.assertEqual(actual['initial_boot_argument_profile'],config['initial_boot_argument_profile'])
                self.assertEqual(actual['cert_fingerprint'],'a'*64 if sample else '')
                self.assertEqual((directory/'report-cert.pem').exists(),sample)
                r.private_write(directory/'token',b'token')
                with patch.object(r,'load_config',lambda _:actual): r.collect(directory)
            self.assertEqual(len(reads),1)
            self.assertEqual([item['phase'] for item in outputs],['public_key','armed'])
            for output in outputs:
                self.assertEqual(output['initial_boot_argument_profile'],config['initial_boot_argument_profile'])
            self.assertEqual((directory/'panic-control').exists(),begin);self.assertEqual((directory/'panic-followup-baseline.json').exists(),begin)
            if begin:
                built=r.json.loads((directory/'panic-control'/'built.json').read_text())
                self.assertEqual(built['control_kind'],'dtrace-begin-v1');self.assertIs(built['permission_verified'],False)
                self.assertEqual((directory/'panic-control'/'program.d').read_bytes(),r.recovery_begin_panic.program(actual['nonce'],context=actual['context']))
                self.assertFalse((directory/'panic-control'/'prepared.json').exists());self.assertFalse((directory/'panic-control'/'launch-attempt.json').exists())

    def test_bootmarker_controller_pins_b1_profile_before_accepting_b2(self):
        for case in ('positive','changed_public','changed_b2','missing_public','sample_positive','sample_mask_missing'):
            with self.subTest(case=case):
                config,facts,current=self.bootmarker_fixture();ctx=config['context']
                if case.startswith('sample_'):
                    ctx['after_debug_boot']='bootargs-marker-sample';config['cert_fingerprint']='a'*64
                if case=='sample_mask_missing':
                    facts.pop('kernel_debug_state');facts['kernel_reader_sample']={'publication':'acknowledged'}
                public={'protocol':'vz-recovery-v1','phase':'public_key','binding':r.binding(ctx),
                        'nonce':config['nonce'],'baseline_boot_uuid':config['baseline'],'public_key':'public',
                        'cert_fingerprint':config['cert_fingerprint'],'debug_boot':True,'debug_source':'bootplist',
                        'after_debug_boot':ctx['after_debug_boot'],'trigger':'reboot-quick',
                        'initial_boot_argument_profile':config['initial_boot_argument_profile']}
                foreign=r.recovery_bootargs.boot_argument_profile(b'foreign=1')
                if case=='missing_public': public.pop('initial_boot_argument_profile')
                final={**public,'phase':'boot_observed','current_boot_uuid':current,'debug_boot_facts':facts,'capture_state':'boot_only'}
                if case=='changed_b2':
                    # A B2 self-reported baseline cannot replace the pinned B1 profile.
                    final['initial_boot_argument_profile']=foreign
                    facts['boot_marker_control']['remaining_profile']={**foreign,'debug_mask':0x102000}
                sequence=[{'id':9,'status':'in_progress','output':{'summary':r.json.dumps(public)}}]
                if case=='changed_public': sequence.append({'id':9,'status':'in_progress','output':{'summary':r.json.dumps({**public,'initial_boot_argument_profile':foreign})}})
                sequence.append({'id':9,'status':'completed','conclusion':'success','output':{'summary':r.json.dumps(final)}})
                checks=iter(sequence);writes=[]
                def api(method,_url,_token,payload=None,**kwargs):
                    if method=='GET': return {'status':'completed'}
                    writes.append(payload);return {}
                with patch.object(r,'list_check',lambda *_:next(checks)),patch.object(r,'api',api), \
                     patch.object(r,'encrypt_token',lambda *_:b'sealed'),patch.object(r.time,'sleep',lambda _:None), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if case in ('positive','sample_positive'): r.controller(ctx,'token')
                    else:
                        with self.assertRaises(ValueError): r.controller(ctx,'token')
                self.assertEqual(len(writes),0 if case=='missing_public' else 1)

    def test_bootmarker_owner_passes_exact_nonce_and_preserves_quick_intent_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);config,_facts,_current=self.bootmarker_fixture();calls=[]
            r.debug_event(directory,config,'request',config['baseline'])
            def stage(_directory,marker,_save,_sync,**options):
                self.assertEqual(options,{'debug_mask':0x102000,'nvram_paniclog':None,'netdump_settings':None,'boot_marker_nonce':config['nonce']})
                raw=r.plistlib.dumps({'Kernel Flags':'preempt=10'})
                staged=r.recovery_bootplist.stage_content(raw,**options)
                self.assertEqual(r.plistlib.loads(staged)['Kernel Flags'],'preempt=10 debug=0x102000 vz_ci_nonce='+config['nonce'])
                calls.append(marker)
                raise r.recovery_bootplist.WriteUncertain()
            def forbidden(*args,**kwargs): self.fail('uncertain staging reached reboot or panic')
            with patch.object(r.recovery_bootplist,'stage',stage),patch.object(r.recovery_bootargs,'csr_allowed',lambda:True), \
                 patch.object(r,'quick_prepare',forbidden),patch.object(r,'quick_reboot_child',forbidden):
                r.debug_owner(directory,config,config['baseline'])
                r.debug_owner(directory,config,config['baseline'])
            self.assertEqual(calls,[r.debug_boot_marker(config)])
            for event in ('staged','intent'): r.debug_event(directory,config,event,config['baseline'])
            r.debug_event(directory,config,'bootplist_staged',config['baseline'],
                          bootplist_stage={'data':'staged','preboot':'staged','metadata_preserved':True})
            r.private_write(directory/'token',b'token')
            ctx=config['context']
            prepared={'protocol':'vz-recovery-v1','phase':'quick_prepared','binding':r.binding(ctx),
                      'nonce':config['nonce'],'baseline_boot_uuid':config['baseline'],'trigger':'reboot-quick',
                      'debug_boot':True,'debug_source':'bootplist','after_debug_boot':'bootargs-marker',
                      'cert_fingerprint':'','initial_boot_argument_profile':config['initial_boot_argument_profile']}
            output={}
            def api(method,_url,_token,payload=None,**kwargs):
                if method=='PATCH': output.update(payload['output']);return {}
                return {'id':9,'name':'Runner recovery '+ctx['run_id'],'head_sha':ctx['sha'],'external_id':r.binding(ctx),
                        'details_url':'https://github.com/Code-Hex/vz-ci-test/runs/9','app':{'id':15368,'slug':'github-actions'},
                        'status':'in_progress','conclusion':None,'output':output}
            with patch.object(r,'api',api),patch.object(r,'boot_uuid',lambda:config['baseline']):
                intent=r.quick_intent_ack(directory,config,prepared)
            self.assertEqual(intent['initial_boot_argument_profile'],config['initial_boot_argument_profile'])
            self.assertEqual(intent['phase'],'quick_intent')

    def syscall_fixture(self):
        config, saved, b3 = self.followup_fixture()
        config['context'].update(after_debug_boot='panic-nonce-syscall', actions='true', repo=r.REPO,
                                 ref='refs/heads/main', event='workflow_dispatch', runner_environment='github-hosted')
        saved['facts'].update(optional_inventory_status='completed',
                             kernel_debug_state={'debug_boot_arg': {'status': 'observed', 'value': 0x102000}})
        return config, saved, b3

    def test_syscall_mode_is_closed_and_requires_existing_panic_proof(self):
        config, saved, b3 = self.syscall_fixture(); ctx = config['context']
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.panic_followup(ctx))
        self.assertTrue(r.report_required(ctx)); self.assertTrue(r.certificate_required(ctx))
        self.assertEqual(r.panic_control_kind(ctx), 'reboot-panic-v1')
        self.assertEqual(r.expected_debug_mask(ctx), 0x102000)
        self.assertFalse(r.nvram_off_control(ctx)); self.assertIsNone(r.netdump_mode(ctx))
        for change in ({'trigger': 'reboot'}, {'debug_boot': False}, {'debug_source': 'nvram'},
                       {'after_debug_boot': 'panic-nonce-syscall-extra'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))
        pending = {'nonce': config['nonce'], 'baseline_boot_uuid': config['baseline'], 'cert_fingerprint': config['cert_fingerprint']}
        trigger = {'scope': saved['scope'], 'helper_sha256': 'f'*64, 'helper_pid': 123, 'ready': True}
        summary = r.followup_summary(config, 'boot_observed', b3, saved, panic_trigger=trigger)
        self.assertEqual(summary['control_kind'], 'reboot-panic-v1'); self.assertEqual(summary['flags'], 3072)
        self.assertTrue(r.debug_lineage_matches(summary, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(summary, '', pending, ctx))
        for change in ({'flags': True}, {'flags': 3072.0}, {'flags': 0x2c00}, {'control_kind': 'usdt-v1'},
                       {'panic_trigger': {**trigger, 'tracer_pid': 456}}, {'panic_trigger': {**trigger, 'helper_pid': True}},
                       {'debug_boot_facts': {**saved['facts'], 'kernel_debug_state': {'debug_boot_arg': {'status': 'observed', 'value': 0}}}}):
            self.assertFalse(r.debug_lineage_matches({**summary, **change}, pending, ctx))
        for mode in ('panic-nonce', 'panic-nonce-usdt', 'panic-nonce-usdt-nvram-off'):
            self.assertFalse(r.boot_proof_matches(summary, pending, {**ctx, 'after_debug_boot': mode}))

    def test_syscall_watch_variant_accepts_only_single_child_trigger(self):
        config, saved, _ = self.syscall_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f'*64)
        self.assertEqual(identity['control_kind'], 'reboot-panic-v1')
        trigger = {'scope': saved['scope'], 'helper_sha256': 'f'*64, 'helper_pid': 123, 'ready': True}
        raw = r.json.dumps(trigger).encode()
        self.assertEqual(r.runtime_watch_release(raw, raw, identity), r.hashlib.sha256(raw).hexdigest())
        for change in ({'tracer_pid': 456}, {'helper_pid': True}, {'helper_pid': 0}, {'ready': False}):
            invalid = r.json.dumps({**trigger, **change}).encode()
            with self.assertRaises(ValueError): r.runtime_watch_release(invalid, invalid, identity)
        for variant in ({k:v for k,v in identity.items() if k != 'control_kind'},
                        {**identity, 'control_kind': 'usdt-v1'}, {**identity, 'control_kind': None}):
            with self.assertRaises(ValueError): r.runtime_watch_release(raw, raw, variant)
        old_config = {**config, 'context': {**config['context'], 'after_debug_boot': 'panic-nonce-usdt'}}
        old = r.runtime_watch_identity(old_config, saved['scope'], 'f'*64)
        self.assertNotIn('control_kind', old)
        old_raw = r.json.dumps({**trigger, 'tracer_pid': 456}).encode()
        self.assertEqual(r.runtime_watch_release(old_raw, old_raw, old), r.hashlib.sha256(old_raw).hexdigest())
        with self.assertRaises(ValueError): r.runtime_watch_release(old_raw, old_raw, identity)

    def test_syscall_saved_mask_gate_prevents_reread_on_b2_and_b3(self):
        config, saved, b3 = self.syscall_fixture(); current = saved['scope']['debug_boot_uuid']
        def forbidden(*args, **kwargs): self.fail('saved syscall proof reread or refire')
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            r.private_write(directory/'panic-followup-debug.json', r.json.dumps(saved).encode())
            r.private_write(directory/'token', b'test-token')
            self.assertEqual(r.read_followup_debug(directory, config), saved)
            captured = []
            for boot in (current, b3):
                with patch.object(r, 'load_config', lambda _:config), patch.object(r, 'boot_uuid', lambda:boot), \
                     patch.object(r.recovery_bootargs, 'kernel_field_state', forbidden), patch.object(r, 'followup_start', forbidden), \
                     patch.object(r, 'followup_finish', lambda _d,_c,_b,value,_t:captured.append(value)):
                    r.collect(directory)
            self.assertEqual(captured, [saved])
            for state in ({'status':'observed','value':0}, {'status':'observed','value':0x102000,'extra':1}, {'status':'unavailable'}):
                bad = copy.deepcopy(saved); bad['facts']['kernel_debug_state']['debug_boot_arg'] = state
                (directory/'panic-followup-debug.json').write_text(r.json.dumps(bad))
                with self.assertRaises(ValueError): r.read_followup_debug(directory, config)

    def test_syscall_mask_precedes_own_prepare_and_latches_failure(self):
        for case in ('positive', 'negative', 'unavailable', 'budget', 'save_error'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp); config, saved, _ = self.syscall_fixture(); calls = []; reports = []
                deadline = r.time.monotonic() + (20 if case == 'budget' else 180)
                original_write = r.private_write
                def read(*args, **kwargs):
                    calls.append('read')
                    if case == 'unavailable': raise OSError('read unavailable')
                    return ('VZKSTATE v1 debug_boot_arg u32 '+str(0 if case == 'negative' else 0x102000)+'\n\n').encode()
                def write(path, data):
                    if case == 'save_error' and path.name == 'panic-followup-debug.json': raise OSError('save failed')
                    return original_write(path, data)
                def prepare(_d, _n, _save, _sync, *, context, deadline):
                    calls.append('prepare'); self.assertEqual(context, config['context'])
                    self.assertTrue(r.kernel_state_proven(r.read_followup_debug(directory, config)['facts']))
                    raise RuntimeError('stop before fire')
                def forbidden(*args, **kwargs): self.fail('wrong control or unproven mask reached fire')
                def complete(_d, _c, _b, _t, output, success, report_deadline):
                    self.assertFalse(success); self.assertTrue(0 < report_deadline-r.time.monotonic() <= 60)
                    reports.append(r.json.loads(output['summary']))
                with patch.object(r.recovery_bootargs, 'capture', read), patch.object(r, 'private_write', write), \
                     patch.object(r.recovery_reboot_panic, 'prepare', prepare), patch.object(r.recovery_reboot_panic, 'fire', forbidden), \
                     patch.object(r.recovery_panic_control, 'prepare', forbidden), patch.object(r.recovery_panic_control, 'fire', forbidden), \
                     patch.object(r, 'start_runtime_watch', forbidden), patch.object(r, 'complete_recovery', complete):
                    r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token', deadline=deadline)
                self.assertEqual(calls, ['read','prepare'] if case == 'positive' else [] if case == 'budget' else ['read'])
                self.assertEqual(len(reports), 1); self.assertEqual(reports[0]['flags'], 3072)
                if case != 'save_error':
                    latched = r.json.loads((directory/'panic-followup-debug.json').read_text())
                    self.assertEqual(latched['facts'], reports[0]['debug_boot_facts'])

    def test_syscall_prepare_fire_and_ack_use_one_kind_and_original_deadline(self):
        for ack in (True, False):
            with self.subTest(ack=ack), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp); config, saved, _ = self.syscall_fixture(); events = []; reports = []
                current = saved['scope']['debug_boot_uuid']; deadline = r.time.monotonic()+180
                prepared = {'helper_sha256':'f'*64}; watch = {'deadline_monotonic':deadline}
                trigger = {'scope':saved['scope'],'helper_sha256':'f'*64,'helper_pid':123,'ready':True}
                def read(*args, **kwargs): return b'VZKSTATE v1 debug_boot_arg u32 1056768\n\n'
                def prepare(_d, _n, _save, _sync, *, context, deadline):
                    self.assertEqual(context, config['context']); self.assertTrue(r.kernel_state_proven(saved['facts']))
                    events.append('prepare'); return prepared
                def publish(_d, _c, _t, summary, _title):
                    self.assertEqual(summary['flags'], 3072); events.append(summary['phase'])
                    if summary['phase'] == 'panic_intent' and not ack: raise OSError('ACK unavailable')
                def fire(_d, scope, value, _save, _sync, ready, current_boot_uuid, *, context, deadline):
                    self.assertEqual(context, config['context']); self.assertEqual(scope, saved['scope'])
                    self.assertEqual(value, prepared); self.assertEqual(deadline, watch['deadline_monotonic']-30)
                    self.assertEqual(current_boot_uuid(), current)
                    events.append('ready')
                    self.assertTrue(ready(trigger))
                    events.append('accepted')
                    return {'phase':'returned','release_status':'released','helper_exit':1,'result':-1,'errno':1,
                            'output_complete':True,'output_overflow':False,'ownership_faults':0}
                def forbidden(*args, **kwargs): self.fail('syscall used DTrace control')
                with patch.object(r.recovery_bootargs,'capture',read), patch.object(r.recovery_reboot_panic,'prepare',prepare), \
                     patch.object(r.recovery_reboot_panic,'fire',fire), patch.object(r.recovery_panic_control,'prepare',forbidden), \
                     patch.object(r.recovery_panic_control,'fire',forbidden), patch.object(r,'publish_followup',publish), \
                     patch.object(r,'start_runtime_watch',lambda *_:watch), patch.object(r,'runtime_watch_alive',lambda *_a,**_k:True), \
                     patch.object(r,'boot_uuid',lambda:current), patch.object(r,'complete_recovery',lambda *_a:reports.append((_a[5],r.json.loads(_a[4]['summary'])))):
                    r.followup_start(directory, config, current, saved['facts'], 'token', deadline=deadline)
                self.assertEqual(events,['prepare','panic_prepared','ready','panic_intent']+(['accepted'] if ack else []))
                self.assertEqual(len(reports),1); self.assertFalse(reports[0][0])
                self.assertEqual(reports[0][1]['panic_control']['status'],'returned' if ack else 'failed')
                self.assertEqual(r.json.loads((directory/'panic-followup-trigger.json').read_text()),trigger)

    def test_syscall_b3_classifier_and_cms_preserve_mode_flags_and_missing_body_failure(self):
        for body in ('fresh', 'missing', 'wrong_nonce', 'wrong_pid'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp); config, saved, b3 = self.syscall_fixture(); trigger = {
                    'scope':saved['scope'],'helper_sha256':'f'*64,'helper_pid':123,'ready':True}
                prepared = {'helper_sha256':'f'*64}; (directory/'panic-control').mkdir()
                for name,value in (('panic-followup-trigger.json',trigger),('panic-control/release-attempt.json',trigger),
                                   ('panic-control/intent.json',{'scope':saved['scope'],'prepared':prepared})):
                    r.private_write(directory/name,r.json.dumps(value).encode())
                r.private_write(directory/'report-cert.pem',b'certificate boundary')
                nonce = '0'*64 if body == 'wrong_nonce' else config['nonce']
                raw = ('panic(cpu 0 caller 0x1): userspace panic: '+r.recovery_nvram_panic.syscall_marker(nonce,124 if body == 'wrong_pid' else 123)+
                       '\nKernel UUID: '+r.KERNEL_UUID+'\n').encode() if body != 'missing' else None
                cipher = b'encrypted boundary'; completed = []; metadata_seen = []
                def validate(_d,_n,value,*,context):
                    self.assertEqual(context,config['context']); self.assertEqual(value,prepared)
                def encrypt(_cert,metadata,report):
                    self.assertEqual(report,raw); metadata_seen.append(metadata)
                    self.assertEqual(metadata['after_debug_boot'],'panic-nonce-syscall')
                    self.assertEqual(metadata['control_kind'],'reboot-panic-v1'); self.assertEqual(metadata['flags'],3072)
                    self.assertEqual(metadata['helper_pid'],123); self.assertEqual(metadata['helper_sha256'],'f'*64)
                    self.assertEqual(set(metadata), {'binding','nonce','kernel_uuid','baseline_boot_uuid','debug_boot_uuid',
                        'current_boot_uuid','source_identity','classification','after_debug_boot','control_kind','flags','helper_pid','helper_sha256'})
                    self.assertEqual(metadata['source_identity'], config['debug_source_identity'])
                    self.assertEqual(metadata['binding'], r.binding(config['context']))
                    self.assertEqual(metadata['nonce'], config['nonce']); self.assertEqual(metadata['kernel_uuid'], r.KERNEL_UUID)
                    self.assertEqual(metadata['baseline_boot_uuid'], config['baseline'])
                    self.assertEqual(metadata['debug_boot_uuid'], saved['scope']['debug_boot_uuid'])
                    self.assertEqual(metadata['current_boot_uuid'], b3)
                    return {'ciphertext':r.base64.b64encode(cipher).decode(),'cipher_sha256':r.hashlib.sha256(cipher).hexdigest(),
                            'cert_fingerprint':config['cert_fingerprint']}
                def forbidden(*args,**kwargs): self.fail('syscall used old classifier or validation')
                with patch.object(r.recovery_reboot_panic,'validate_prepared',validate), patch.object(r.recovery_panic_control,'validate_prepared',forbidden), \
                     patch.object(r.recovery_nvram_panic,'classify_usdt',forbidden),patch.object(r.recovery_nvram_panic,'classify',forbidden), \
                     patch.object(r.recovery_nvram_panic,'read_panic_info',lambda:('observed' if raw else 'unavailable',raw)), \
                     patch.object(r.recovery_reports,'encrypt_bundle',encrypt), \
                     patch.object(r,'complete_recovery',lambda *_a:completed.append((_a[5],r.json.loads(_a[4]['summary'])))):
                    r.followup_finish(directory,config,b3,saved,'token')
                self.assertEqual(len(metadata_seen),int(raw is not None)); self.assertEqual(completed[0][0],body=='fresh')
                self.assertEqual(completed[0][1]['flags'],3072)
                self.assertEqual(completed[0][1]['capture_state'],'fresh_fragment' if body=='fresh' else 'unavailable' if body=='missing' else 'encrypted_unvalidated')

    def test_syscall_b3_rejects_malformed_or_two_child_trigger_before_capture(self):
        for change in ({'tracer_pid':456}, {'helper_pid':True}, {'helper_pid':0}, {'ready':False}, {'extra':1}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp); config,saved,b3=self.syscall_fixture(); (directory/'panic-control').mkdir()
                trigger={'scope':saved['scope'],'helper_sha256':'f'*64,'helper_pid':123,'ready':True,**change}
                for name,value in (('panic-followup-trigger.json',trigger),('panic-control/release-attempt.json',trigger),
                                   ('panic-control/intent.json',{'scope':saved['scope'],'prepared':{'helper_sha256':'f'*64}})):
                    r.private_write(directory/name,r.json.dumps(value).encode())
                def forbidden(*args,**kwargs): self.fail('invalid trigger reached validation/capture/encryption')
                with patch.object(r.recovery_reboot_panic,'validate_prepared',forbidden), \
                     patch.object(r.recovery_nvram_panic,'read_panic_info',forbidden), \
                     patch.object(r.recovery_reports,'encrypt_bundle',forbidden):
                    with self.assertRaises(ValueError): r.followup_finish(directory,config,b3,saved,'token')

    def test_kernel_state_mode_has_no_panic_or_certificate_path(self):
        ctx = {'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
               'runner_environment': 'github-hosted', 'run_id': '123', 'attempt': '1', 'sha': 'a' * 40,
               'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'bootplist', 'after_debug_boot': 'kernel-state'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.kernel_state_mode(ctx))
        self.assertFalse(r.panic_followup(ctx))
        self.assertFalse(r.report_required(ctx))
        self.assertFalse(r.certificate_required(ctx))
        self.assertIsNone(r.netdump_mode(ctx))
        self.assertEqual(r.expected_debug_mask(ctx), 0x102000)
        for change in ({'trigger': 'reboot'}, {'debug_boot': False}, {'debug_source': 'nvram'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))

    def test_kernel_state_bootproof_requires_the_saved_runtime_mask(self):
        config, saved, _b3 = self.followup_fixture()
        ctx = {**config['context'], 'after_debug_boot': 'kernel-state'}
        pending = {'nonce': config['nonce'], 'baseline_boot_uuid': config['baseline'], 'cert_fingerprint': ''}
        facts = {**saved['facts'], 'optional_inventory_status': 'completed',
                 'kernel_debug_state': {'debug_boot_arg': {'status': 'observed', 'value': 0x102000},
                                        'coprocessor_paniclog_flush': {'status': 'unavailable'}}}
        data = {'protocol': 'vz-recovery-v1', 'phase': 'boot_observed', 'binding': r.binding(ctx), **pending,
                'current_boot_uuid': saved['scope']['debug_boot_uuid'], 'trigger': 'reboot-quick',
                'debug_boot': True, 'debug_source': 'bootplist', 'after_debug_boot': 'kernel-state',
                'debug_boot_facts': facts}
        self.assertTrue(r.kernel_state_proven(facts))
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        for state in ({'status': 'unavailable'}, {'status': 'invalid'}, {'status': 'observed', 'value': 0},
                      {'status': 'observed', 'value': 1056768.0}, {'status': 'observed', 'value': '1056768'}):
            bad = {**facts, 'kernel_debug_state': {'debug_boot_arg': state}}
            self.assertFalse(r.kernel_state_proven(bad))
            self.assertFalse(r.boot_proof_matches({**data, 'debug_boot_facts': bad}, pending, ctx))
        self.assertFalse(r.kernel_state_proven({**facts, 'optional_inventory_status': 'uncertain'}))

    def test_usdt_runtime_mask_requires_exact_critical_variant(self):
        facts={'optional_inventory_status':'completed','kernel_debug_state':{'debug_boot_arg':{'status':'observed','value':0x102000}}}
        self.assertTrue(r.kernel_state_proven(facts))
        for state in ({'status':'observed','value':True},{'status':'observed','value':0},
                      {'status':'observed','value':0x102000,'error':{}},
                      {'status':'observed','value':0x102000,'extra':1},{'status':'unavailable'}):
            self.assertFalse(r.kernel_state_proven({**facts,'kernel_debug_state':{'debug_boot_arg':state}}))

    def test_usdt_mask_observation_latches_before_prepare_and_negative_never_fires(self):
        for case in ('positive','zero','read_error','save_error','budget'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp); config,saved,_=self.followup_fixture()
                config['context']['after_debug_boot']='panic-nonce-usdt'
                current=saved['scope']['debug_boot_uuid']; reads=[]; prepared=[]; reports=[]
                deadline=r.time.monotonic()+(31 if case=='budget' else 180)
                actual_capture=r.recovery_bootargs.capture; actual_write=r.private_write
                def read(argv,limit,timeout,*,capture_stderr):
                    reads.append(1)
                    self.assertEqual((limit,timeout,capture_stderr),(4096,30,True))
                    if case=='read_error': raise RuntimeError('synthetic observation failure')
                    raw='VZKSTATE v1 debug_boot_arg u32 '+str(0 if case=='zero' else 0x102000)+'\n\n'
                    return actual_capture([r.sys.executable,'-c','print('+repr(raw)+',end="")'],limit,timeout,capture_stderr=True)
                def write(path,data):
                    if case=='save_error' and path.name=='panic-followup-debug.json': raise OSError('synthetic save failure')
                    return actual_write(path,data)
                def prepare(*args,**kwargs):
                    prepared.append(1)
                    self.assertEqual(case,'positive')
                    self.assertEqual(kwargs['deadline'],deadline)
                    self.assertTrue(r.kernel_state_proven(r.read_followup_debug(directory,config)['facts']))
                    raise RuntimeError('stop at nonfaulting preparation boundary')
                def forbidden(*args,**kwargs): self.fail('negative mask reached watch/fire')
                def complete(_d,_c,_b,_t,output,success,reported_deadline):
                    self.assertFalse(success)
                    self.assertTrue(0 < reported_deadline-r.time.monotonic() <= 60)
                    reports.append(r.json.loads(output['summary']))
                with patch.object(r.recovery_bootargs,'capture',read),patch.object(r,'private_write',write), \
                     patch.object(r.recovery_panic_control,'prepare',prepare),patch.object(r.recovery_panic_control,'fire',forbidden), \
                     patch.object(r,'start_runtime_watch',forbidden),patch.object(r,'complete_recovery',complete):
                    r.followup_start(directory,config,current,saved['facts'],'token',deadline=deadline)
                self.assertEqual(prepared,[1] if case=='positive' else [])
                self.assertEqual(len(reads),0 if case=='budget' else 1)
                self.assertEqual(len(reports),1)
                self.assertEqual(reports[0]['phase'],'panic_returned')
                if case!='save_error':
                    latched=r.json.loads((directory/'panic-followup-debug.json').read_text())
                    self.assertEqual(latched['facts'],reports[0]['debug_boot_facts'])

    def test_usdt_saved_mask_gates_watch_and_controller_and_collect_never_rereads(self):
        config,saved,b3=self.followup_fixture(); config['context']['after_debug_boot']='panic-nonce-usdt'
        config['python']=r.sys.executable
        saved['facts'].update(optional_inventory_status='completed',kernel_debug_state={'debug_boot_arg':{'status':'observed','value':0x102000}})
        trigger={'scope':saved['scope'],'helper_sha256':'f'*64,'helper_pid':123,'tracer_pid':456,'ready':True}
        pending={'baseline_boot_uuid':config['baseline'],'nonce':config['nonce'],'cert_fingerprint':config['cert_fingerprint']}
        def forbidden(*args,**kwargs): self.fail('saved proof caused native reread/fire/API')
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); path=directory/'panic-followup-debug.json'
            r.private_write(path,r.json.dumps(saved).encode())
            for phase in ('panic_prepared','panic_intent','boot_observed'):
                data=r.followup_summary(config,phase,b3,saved,panic_trigger=trigger)
                self.assertEqual(data['debug_boot_facts'],saved['facts'])
                self.assertTrue(r.debug_lineage_matches(data,pending,config['context']))
            with patch.object(r,'load_config',lambda _:config),patch.object(r,'boot_uuid',lambda:saved['scope']['debug_boot_uuid']), \
                 patch.object(r.recovery_bootargs,'kernel_field_state',forbidden),patch.object(r,'followup_start',forbidden):
                r.collect(directory)
            r.private_write(directory/'token',b'test-token')
            received=[]
            with patch.object(r,'load_config',lambda _:config),patch.object(r,'boot_uuid',lambda:b3), \
                 patch.object(r.recovery_bootargs,'kernel_field_state',forbidden),patch.object(r,'followup_finish',lambda _d,_c,_b,value,_t:received.append(value)):
                r.collect(directory)
            self.assertEqual(received,[saved])
            for state in ({'status':'observed','value':0},{'status':'observed','value':True},
                          {'status':'observed','value':0x102000,'extra':1},{'status':'unavailable'}):
                invalid=copy.deepcopy(saved); invalid['facts']['kernel_debug_state']['debug_boot_arg']=state
                path.write_text(r.json.dumps(invalid))
                with self.assertRaises(ValueError): r.read_followup_debug(directory,config)
                data=r.followup_summary(config,'boot_observed',b3,invalid,panic_trigger=trigger)
                self.assertFalse(r.debug_lineage_matches(data,pending,config['context']))
                for current in (saved['scope']['debug_boot_uuid'],b3):
                    with patch.object(r,'load_config',lambda _:config),patch.object(r,'boot_uuid',lambda:current), \
                         patch.object(r.recovery_bootargs,'kernel_field_state',forbidden), \
                         patch.object(r,'followup_start',forbidden),patch.object(r,'followup_finish',forbidden):
                        with self.assertRaises(ValueError): r.collect(directory)
                with patch.object(r,'load_config',lambda _:config),patch.object(r,'boot_uuid',lambda:saved['scope']['debug_boot_uuid']), \
                     patch.object(r,'runtime_watch_executable_matches',lambda *_:True),patch.object(r,'api',forbidden), \
                     patch.object(r.recovery_bootargs,'kernel_field_state',forbidden):
                    with self.assertRaises(ValueError): r.runtime_watch(directory)

    def usdt_off_fixture(self):
        config, saved, b3 = self.followup_fixture()
        config['context']['after_debug_boot'] = 'panic-nonce-usdt-nvram-off'
        control = r.parse_nvram_off_control('alpha=1 nvram_paniclog=0 debug=0x102000')
        saved['facts'].update(optional_inventory_status='completed',
            kernel_debug_state={'debug_boot_arg': {'status': 'observed', 'value': 0x102000}},
            nvram_paniclog_control=control,
            boot_argument_profiles={'initial': r.recovery_bootargs.boot_argument_profile('alpha=1'),
                                    'postboot': control['full_profile']})
        return config, saved, b3

    def test_usdt_nvram_off_is_a_distinct_closed_mode(self):
        config, _, _ = self.usdt_off_fixture()
        ctx = {**config['context'], 'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main',
               'event': 'workflow_dispatch', 'runner_environment': 'github-hosted'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.panic_followup(ctx))
        self.assertTrue(r.report_required(ctx))
        self.assertTrue(r.certificate_required(ctx))
        self.assertTrue(r.nvram_off_control(ctx))
        self.assertTrue(r.mode_matches(ctx, {}, ctx))
        self.assertIsNone(r.netdump_mode(ctx))
        self.assertEqual(r.panic_control_kind(ctx), 'usdt-v1')
        self.assertEqual(r.expected_debug_mask(ctx), 0x102000)
        for change in ({'trigger': 'reboot'}, {'debug_boot': False}, {'debug_source': 'nvram'},
                       {'after_debug_boot': 'panic-nonce-usdt-nvram-off-extra'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))
        for mode, kind, off in (('panic-nonce-usdt', 'usdt-v1', False),
                                ('panic-nonce-nvram-off', 'pid-v1', True), ('panic-nonce', 'pid-v1', False)):
            other = {**ctx, 'after_debug_boot': mode}
            self.assertEqual(r.panic_control_kind(other), kind)
            self.assertEqual(r.nvram_off_control(other), off)
            self.assertFalse(r.mode_matches({**ctx, 'after_debug_boot': mode}, {}, ctx))

    def test_usdt_nvram_off_requires_both_saved_proofs_without_reread(self):
        config, saved, b3 = self.usdt_off_fixture()
        trigger = {'scope': saved['scope'], 'helper_sha256': 'f'*64, 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        pending = {'nonce': config['nonce'], 'baseline_boot_uuid': config['baseline']}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for missing in (None, 'nvram_paniclog_control', 'kernel_debug_state'):
                facts = {k: v for k, v in saved['facts'].items() if k != missing}
                record = {**saved, 'facts': facts}
                (directory/'panic-followup-debug.json').unlink(missing_ok=True)
                r.private_write(directory/'panic-followup-debug.json', r.json.dumps(record).encode())
                data = r.followup_summary(config, 'boot_observed', b3, record, panic_trigger=trigger)
                with patch.object(r.recovery_bootargs, 'kernel_field_state', lambda *_a, **_k: self.fail('B3 mask reread')):
                    self.assertEqual(r.debug_lineage_matches(data, pending, config['context']), missing is None)
                    if missing is None:
                        self.assertEqual(r.read_followup_debug(directory, config), record)
                    else:
                        with self.assertRaises(ValueError): r.read_followup_debug(directory, config)

    def test_usdt_nvram_off_both_gates_control_preparation(self):
        for bad in ('mask', 'off', None):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp); config, saved, _ = self.usdt_off_fixture(); reports = []; prepared = []
                if bad == 'off': del saved['facts']['nvram_paniclog_control']
                def read(_argv, _limit, timeout, *, capture_stderr):
                    return ('VZKSTATE v1 debug_boot_arg u32 '+str(0 if bad == 'mask' else 0x102000)+'\n\n').encode()
                def forbidden(*_a, **_k): self.fail('negative control reached prepare/watch/fire')
                def prepare(*_a, **kwargs):
                    self.assertIsNone(bad)
                    self.assertEqual(kwargs['control_kind'], 'usdt-v1')
                    prepared.append(True)
                    raise RuntimeError('stop at nonfaulting preparation boundary')
                with patch.object(r.recovery_bootargs, 'capture', read), \
                     patch.object(r.recovery_panic_control, 'prepare', prepare), \
                     patch.object(r.recovery_panic_control, 'fire', forbidden), \
                     patch.object(r, 'start_runtime_watch', forbidden), \
                     patch.object(r, 'complete_recovery', lambda *_a: reports.append(_a[5])):
                    r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
                self.assertEqual(reports, [False])
                self.assertEqual(prepared, [True] if bad is None else [])
                latched = r.json.loads((directory/'panic-followup-debug.json').read_text())
                self.assertEqual(latched['facts']['kernel_debug_state']['debug_boot_arg']['value'], 0 if bad == 'mask' else 0x102000)

    def test_usdt_nvram_off_cms_exact_mode_and_missing_body_is_not_success(self):
        for has_raw in (True, False):
            with self.subTest(has_raw=has_raw), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp); config, saved, b3 = self.usdt_off_fixture(); scope = saved['scope']
                trigger = {'scope': scope, 'helper_sha256': 'f'*64, 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
                prepared = {'helper_sha256': 'f'*64}; (directory/'panic-control').mkdir()
                for name, value in (('panic-followup-trigger.json', trigger), ('panic-control/release-attempt.json', trigger),
                                    ('panic-control/intent.json', {'scope': scope, 'prepared': prepared})):
                    r.private_write(directory/name, r.json.dumps(value).encode())
                r.private_write(directory/'report-cert.pem', b'certificate boundary')
                raw = ('panic(cpu 0 caller 0x1): dtrace: panic action at probe vzobsddddddddddddddddp123:helper:vz_nonce_'+
                       config['nonce']+':observe (ecb 0x1)\nKernel UUID: '+r.KERNEL_UUID+'\n').encode() if has_raw else None
                cipher = b'encrypted boundary'; metadata_seen = []; completed = []
                envelope = {'ciphertext': r.base64.b64encode(cipher).decode(), 'cipher_sha256': r.hashlib.sha256(cipher).hexdigest(),
                            'cert_fingerprint': config['cert_fingerprint']}
                def encrypt(_cert, metadata, body):
                    self.assertEqual(body, raw); metadata_seen.append(metadata)
                    self.assertEqual(metadata['after_debug_boot'], 'panic-nonce-usdt-nvram-off')
                    self.assertEqual(metadata['control_kind'], 'usdt-v1')
                    self.assertEqual(metadata['helper_pid'], 123)
                    return envelope
                with patch.object(r.recovery_panic_control, 'validate_prepared', lambda *_a, **_k: directory/'helper'), \
                     patch.object(r.recovery_nvram_panic, 'read_panic_info', lambda: ('observed' if has_raw else 'unavailable', raw)), \
                     patch.object(r.recovery_reports, 'encrypt_bundle', encrypt), \
                     patch.object(r, 'complete_recovery', lambda *_a: completed.append((_a[5], r.json.loads(_a[4]['summary'])))):
                    r.followup_finish(directory, config, b3, saved, 'token')
                self.assertEqual(len(metadata_seen), int(has_raw))
                success, summary = completed[0]
                self.assertEqual(success, has_raw)
                self.assertEqual(summary['after_debug_boot'], 'panic-nonce-usdt-nvram-off')
                self.assertEqual(summary['debug_boot_facts'], saved['facts'])
                self.assertEqual(summary['capture_state'], 'fresh_fragment' if has_raw else 'unavailable')

    def test_usdt_followup_is_local_and_uses_a_closed_control_kind(self):
        ctx = {'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
               'runner_environment': 'github-hosted', 'run_id': '123', 'attempt': '1', 'sha': 'a' * 40,
               'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'bootplist', 'after_debug_boot': 'panic-nonce-usdt'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.panic_followup(ctx))
        self.assertTrue(r.report_required(ctx))
        self.assertTrue(r.certificate_required(ctx))
        self.assertIsNone(r.netdump_mode(ctx))
        self.assertEqual(r.expected_debug_mask(ctx), 0x102000)
        self.assertEqual(r.panic_control_kind(ctx), 'usdt-v1')
        for mode in ('none', 'panic-nonce', 'panic-nonce-nvram-off', 'netdump-prime', 'panic-nonce-netdump'):
            self.assertEqual(r.panic_control_kind({**ctx, 'after_debug_boot': mode}), 'pid-v1')
        for change in ({'trigger': 'reboot'}, {'debug_boot': False}, {'debug_source': 'nvram'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))

    def test_followup_classifier_binds_usdt_to_the_actual_trigger_pid(self):
        config = {'nonce': 'd' * 64, 'context': {'after_debug_boot': 'panic-nonce-usdt'}}
        suffix = (' (ecb 0x1)\nKernel UUID: ' + r.KERNEL_UUID + '\n\0').encode()
        usdt = ('panic(cpu 0 caller 0x1): dtrace: panic action at probe vzobsddddddddddddddddp123:helper:vz_nonce_' +
                'd' * 64 + ':observe').encode() + suffix
        pid = ('panic(cpu 0 caller 0x1): dtrace: panic action at probe pid123:helper:vz_nonce_' +
               'd' * 64 + ':entry').encode() + suffix
        trigger = {'helper_pid': 123}
        self.assertEqual(r.classify_followup(usdt, config, trigger)['freshness'], 'verified')
        self.assertEqual(r.classify_followup(usdt, config, {'helper_pid': 124})['freshness'], 'unverified')
        self.assertEqual(r.classify_followup(pid, config, trigger)['freshness'], 'unverified')
        config['context']['after_debug_boot'] = 'panic-nonce'
        self.assertEqual(r.classify_followup(pid, config, trigger)['freshness'], 'verified')
        self.assertEqual(r.classify_followup(usdt, config, trigger)['freshness'], 'unverified')

    def capture_fixture(self):
        config, saved, b3 = self.followup_fixture()
        ctx = config['context']
        ctx['after_debug_boot'] = 'panic-nonce-netdump'
        config['debug_boot'] = True
        n = r.recovery_netdump
        profile = r.recovery_bootargs.boot_argument_profile('')
        config['initial_boot_argument_profile'] = profile
        core, network = n.source_identity(r.__file__)
        offer = n.ReceiverOffer(r.binding(ctx), 'c' * 32, n.Endpoint('1.1.1.1', 10248), 43210,
                                config['cert_fingerprint'], core, network, 'capture')
        settings = r.recovery_netdump_settings.NetdumpSettings('1.1.1.1', '192.168.64.1', 10248, config['nonce'][:16])
        plan = n.DiscoveryPlan(offer, config['nonce'], n.Endpoint('8.8.8.8', 40000), '192.168.64.2', 'en0', settings,
                               n.HelloStats(True, True, 10), n.BootBaseline.from_profile(config['baseline'], profile))
        config['netdump_plan'] = plan.record()
        current = saved['scope']['debug_boot_uuid']
        scope = r.netdump_scope(config, current)
        facts = saved['facts']
        facts['active_debug_mask'] = 0x22040
        facts['netdump_active_control'] = r.recovery_netdump_settings.active_control('debug=0x22040 ' + ' '.join(settings.tokens()), settings, profile)
        facts['owner_events'] = [{'event': event, 'source_identity': core, 'actual_boot_uuid': config['baseline']}
                                for event in ('staged', 'bootplist_staged', 'intent')]
        facts['owner_events'][1]['bootplist_stage'] = {'data': 'staged', 'preboot': 'staged', 'metadata_preserved': True}
        base = {'protocol': 'vz-recovery-v1', 'phase': 'boot_core', 'binding': r.binding(ctx), 'nonce': config['nonce'],
                'baseline_boot_uuid': config['baseline'], 'current_boot_uuid': current, 'trigger': 'reboot-quick',
                'cert_fingerprint': config['cert_fingerprint'], 'debug_boot': True, 'debug_source': 'bootplist',
                'after_debug_boot': ctx['after_debug_boot'], 'debug_boot_facts': facts}
        check = {'id': config['check_id'], 'name': 'Runner recovery 123', 'head_sha': ctx['sha'], 'external_id': r.binding(ctx),
                 'app': {'id': 15368, 'slug': 'github-actions'}, 'details_url': r.API.replace('api.github.com/repos', 'github.com') + '/runs/' + str(config['check_id']),
                 'status': 'in_progress', 'conclusion': None, 'output': {'title': 'Boot core recovered', 'summary': r.json.dumps(base), 'text': ''}}
        snapshot = n.core_snapshot(check, scope, plan.public_fact())
        host = n.prime_host_fact(plan, scope, n.Endpoint('8.8.8.8', 40001), snapshot, n.HelloStats(True, True, 20))
        proof = n.make_prime_proof(offer, plan.public_fact(), host, n.HelloStats(True, True, 20), snapshot, 12, 11)
        facts['netdump_prime'] = {'status': 'verified', 'proof': proof}
        prepared = {key: 'f' * 64 for key in ('control_sha256', 'preflight_sha256', 'getter_sha256', 'helper_source_sha256', 'helper_sha256')}
        prepared.update(nonce_sha256=r.hashlib.sha256(config['nonce'].encode()).hexdigest(), observe_status='passed', compile_status='passed')
        trigger = {'scope': saved['scope'], 'helper_sha256': prepared['helper_sha256'], 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        intent = r.followup_summary(config, 'panic_intent', current, saved, prepared=prepared, panic_trigger=trigger, result_owner='capture-controller')
        check['output'] = {'title': 'Nonce panic intent durable', 'summary': r.json.dumps(intent), 'text': ''}
        pending = {'nonce': config['nonce'], 'baseline_boot_uuid': config['baseline'],
                   'cert_fingerprint': config['cert_fingerprint'], 'check_id': config['check_id']}
        return config, saved, intent, check, pending, prepared

    def test_netdump_capture_mode_keeps_legacy_report_and_b3_semantics(self):
        ctx = {'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
               'runner_environment': 'github-hosted', 'run_id': '123', 'attempt': '1', 'sha': 'a' * 40,
               'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'bootplist', 'after_debug_boot': 'panic-nonce-netdump'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertEqual(r.netdump_mode(ctx), 'capture')
        self.assertTrue(r.netdump_capture(ctx))
        self.assertTrue(r.certificate_required(ctx))
        self.assertFalse(r.report_required(ctx))
        self.assertFalse(r.panic_followup(ctx))
        self.assertEqual(r.expected_debug_mask(ctx), 0x22040)
        for change in ({'trigger': 'reboot'}, {'debug_boot': False}, {'debug_source': 'nvram'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))

    def test_capture_duplicate_collect_returns_before_boot_query_token_or_b3_capture(self):
        config, _saved, _b3 = self.followup_fixture()
        config['context']['after_debug_boot'] = 'panic-nonce-netdump'
        for filename in ('panic-followup-debug.json', 'capture-handoff-started.json'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                r.private_write(directory / filename, b'{partial')
                def forbidden(*_args, **_kwargs): self.fail('duplicate capture collect performed work')
                with patch.object(r, 'load_config', return_value=config), patch.object(r, 'boot_uuid', forbidden), \
                     patch.object(r, 'followup_finish', forbidden), patch.object(r, 'api', forbidden):
                    r.collect(directory)

    def test_capture_writer_fence_is_distinct_from_the_followup_dedup_marker(self):
        config, saved, _b3 = self.followup_fixture()
        config['context']['after_debug_boot'] = 'panic-nonce-netdump'
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            r.private_write(directory / 'panic-followup-debug.json', b'{}')
            r.require_root_writer(directory, config)
            r.private_write(directory / 'capture-handoff-started.json', b'{partial')
            def forbidden(*_args, **_kwargs): self.fail('fenced writer attempted API')
            with patch.object(r, 'api', forbidden):
                for writer in (
                    lambda: r.publish_debug_core(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token'),
                    lambda: r.publish_followup(directory, config, 'token', {}, 'forbidden'),
                    lambda: r.complete_recovery(directory, config, saved['scope']['debug_boot_uuid'], 'token', {}, False, 0)):
                    with self.assertRaises(ValueError): writer()

    def test_capture_intent_marker_precedes_an_uncertain_root_patch(self):
        config, _saved, intent, _check, _pending, _prepared = self.capture_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            calls = []
            def api(method, url, _token, payload=None, **_kwargs):
                self.assertEqual((method, url), ('PATCH', r.CHECKS + '/9'))
                record = r.json.loads((directory / 'capture-handoff-started.json').read_text())
                self.assertEqual(record['intent_sha256'], r.recovery_netdump.digest(intent))
                self.assertEqual(record['scope']['helper_pid'], 123)
                self.assertEqual(r.json.loads(payload['output']['summary'])['result_owner'], 'capture-controller')
                calls.append('patch')
                raise TimeoutError('unknown_server_commit')
            with patch.object(r, 'api', api):
                with self.assertRaises(TimeoutError): r.publish_capture_intent(directory, config, 'token', intent)
                with self.assertRaises(ValueError): r.complete_recovery(directory, config, intent['current_boot_uuid'], 'token', {}, False, 0)
            self.assertEqual(calls, ['patch'])

    def test_capture_controller_failure_without_committed_handoff_never_patches_root(self):
        config, _saved, _intent, check, _pending, _prepared = self.capture_fixture()
        check['output']['summary'] = r.json.dumps({'phase': 'armed'})
        calls = []
        def api(method, *_args, **_kwargs):
            calls.append(method)
            return check
        def stop(_seconds): raise RuntimeError('controller_stopped_before_handoff')
        with patch.object(r, 'list_check', return_value=check), patch.object(r, 'api', api), \
             patch.object(r.time, 'sleep', stop), patch.object(r.signal, 'signal', lambda *_: None):
            with self.assertRaises(RuntimeError): r.controller(config['context'], 'token')
        self.assertEqual(calls, [])

    def test_capture_controller_close_rechecks_exact_owner_intent_and_preserves_bookkeeping(self):
        config, _saved, intent, check, pending, _prepared = self.capture_fixture()
        snapshot = r.capture_intent_snapshot(check, pending, config['context'])
        for mutation in ('owner', 'intent', 'completed_failure'):
            server = copy.deepcopy(check)
            if mutation == 'completed_failure': server.update(status='completed', conclusion='failure')
            else:
                summary = r.json.loads(server['output']['summary'])
                if mutation == 'owner': summary['result_owner'] = 'other'
                else: summary['panic_trigger']['helper_pid'] = 124
                server['output']['summary'] = r.json.dumps(summary)
            calls = []
            def api(method, *_args, **_kwargs):
                calls.append(method)
                return server
            with self.subTest(mutation=mutation), patch.object(r, 'api', api), self.assertRaises(ValueError):
                r.close_capture_root(config['context'], 'token', pending, snapshot, 13, False)
            self.assertEqual(calls, ['GET'])
        server, calls = copy.deepcopy(check), []
        def api(method, _url, _token, payload=None, **_kwargs):
            calls.append(method)
            if method == 'PATCH': server.update(copy.deepcopy(payload))
            result = copy.deepcopy(server)
            if result['status'] == 'completed': result['output']['text'] = None
            return result
        with patch.object(r, 'api', api): r.close_capture_root(config['context'], 'token', pending, snapshot, 13, True)
        self.assertEqual(calls, ['GET', 'PATCH', 'GET'])
        self.assertEqual(server['conclusion'], 'neutral')
        book = r.json.loads(server['output']['summary'])['capture_bookkeeping']
        self.assertEqual(book, {'intent_sha256': r.recovery_netdump.digest(intent), 'scope': snapshot['scope'], 'receiver_check_id': 13, 'captured': True})

    def test_capture_runtime_watch_has_a_distinct_finite_budget_without_changing_legacy(self):
        config, saved, _b3 = self.followup_fixture()
        legacy = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        self.assertNotIn('lifetime_seconds', legacy)
        config['context']['after_debug_boot'] = 'panic-nonce-netdump'
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        self.assertEqual(identity['lifetime_seconds'], 240)
        started = 17.000000001
        receipt = {'identity': identity, 'check_id': 17, 'pid': 123, 'started_monotonic': started,
                   'deadline_monotonic': started + 240, 'acknowledged': True}
        self.assertEqual(r.runtime_watch_ready(receipt, identity, 123, 16, 30), started + 240)
        with self.assertRaises(ValueError): r.runtime_watch_ready(receipt, identity, 123, 16, 100)
        with self.assertRaises(ValueError): r.runtime_watch_ready({**receipt, 'deadline_monotonic': started + 120}, identity, 123, 16, 30)

    def test_capture_handoff_uncertainty_and_fire_return_never_complete_the_root_check(self):
        for outcome in ('patch_unknown', 'marker_write_failed', 'bad_arm', 'returned'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, saved, _intent, root, _pending, prepared = self.capture_fixture()
                current = saved['scope']['debug_boot_uuid']
                r.private_write(directory / 'report-cert.pem', b'public certificate fixture')
                root_phases, fire_status, releases = [], {}, []
                def prepare(*_args, **_kwargs):
                    (directory / 'panic-control').mkdir()
                    return prepared
                def api(method, url, _token, payload=None, **_kwargs):
                    if url == r.CHECKS + '/9':
                        if method == 'PATCH':
                            phase = r.json.loads(payload['output']['summary'])['phase']
                            root_phases.append(phase)
                            self.assertNotEqual(payload.get('status'), 'completed')
                            root.update(copy.deepcopy(payload))
                            if phase == 'panic_intent':
                                self.assertTrue((directory / 'capture-handoff-started.json').exists())
                                if outcome == 'patch_unknown': raise TimeoutError('unknown_patch_commit')
                        return copy.deepcopy(root)
                    if method == 'POST':
                        self.assertTrue(payload['name'].startswith('Capture fire status '))
                        fire_status.update(copy.deepcopy(payload), id=17, app={'id': 15368, 'slug': 'github-actions'},
                                           details_url='https://github.com/Code-Hex/vz-ci-test/runs/17')
                        return copy.deepcopy(fire_status)
                    self.assertEqual((method, url), ('GET', r.CHECKS + '/17'))
                    return copy.deepcopy(fire_status)
                original_save = r.private_write
                def save(path, data):
                    if outcome == 'marker_write_failed' and path.name == 'capture-handoff-started.json':
                        raise OSError('handoff_storage_failed')
                    original_save(path, data)
                def arm(_ctx, _token, proof, intent, root_id, deadline):
                    self.assertEqual(root_id, 9)
                    self.assertGreaterEqual(deadline - r.time.monotonic(), 70)
                    if outcome == 'bad_arm': return None
                    scope = r.recovery_netdump_capture.CaptureScope.from_trigger(r.netdump_scope(config, current).record(),
                        r.recovery_netdump.digest(intent), intent['panic_trigger'])
                    return r.recovery_netdump_capture.make_armed(scope, prime_proof_sha256=r.recovery_netdump.digest(proof),
                        offer_digest=r.recovery_netdump.digest(proof['offer']), peer=proof['host_plan']['intel_public_endpoint'], receiver_check_id=13)
                def fire(_directory, scope, _prepared, _save, _sync, ready, _boot, **_kwargs):
                    trigger = {'scope': scope, 'helper_sha256': prepared['helper_sha256'], 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
                    if ready(trigger): releases.append('G')
                    return {'phase': 'returned', 'release_status': 'released', 'raw': 'private_return_must_not_leak'}
                def forbidden(*_args, **_kwargs): self.fail('handoff path used Root completion')
                watch = {'child': object(), 'deadline_monotonic': r.time.monotonic() + 240}
                with patch.object(r.recovery_panic_control, 'prepare', prepare), patch.object(r.recovery_panic_control, 'fire', fire), \
                     patch.object(r, 'api', api), patch.object(r, 'private_write', save), \
                     patch.object(r.recovery_netdump, 'arm_capture', arm), patch.object(r, 'start_runtime_watch', return_value=watch), \
                     patch.object(r, 'runtime_watch_alive', return_value=True), patch.object(r, 'boot_uuid', return_value=current), \
                     patch.object(r, 'complete_recovery', forbidden):
                    r.followup_start(directory, config, current, saved['facts'], 'token')
                self.assertEqual(root_phases, ['panic_prepared'] if outcome == 'marker_write_failed' else ['panic_prepared', 'panic_intent'])
                self.assertEqual(releases, ['G'] if outcome == 'returned' else [])
                self.assertEqual(fire_status['conclusion'], 'neutral')
                summary = r.json.loads(fire_status['output']['summary'])
                self.assertIs(summary['handoff_attempted'], True)
                self.assertNotIn('private_return_must_not_leak', r.json.dumps(fire_status))

    def test_capture_failure_before_handoff_keeps_mac_root_completion_authority(self):
        config, saved, _intent, _check, _pending, _prepared = self.capture_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            directory, events = Path(tmp), []
            def fail(*_args, **_kwargs): raise TimeoutError('prepare_failed')
            def complete(_directory, _config, _current, _token, output, successful, _deadline):
                r.require_root_writer(directory, config)
                self.assertFalse(successful)
                self.assertFalse((directory / 'capture-handoff-started.json').exists())
                self.assertEqual(r.json.loads(output['summary'])['phase'], 'panic_returned')
                events.append('root_failure')
            def forbidden(*_args, **_kwargs): self.fail('pre-handoff failure reached fire status')
            with patch.object(r.recovery_panic_control, 'prepare', fail), patch.object(r, 'complete_recovery', complete), \
                 patch.object(r, 'publish_capture_fire_status', forbidden):
                r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertEqual(events, ['root_failure'])

    def test_capture_collect_orders_restore_core_prime_followup_without_b3_or_inventory(self):
        config, saved, _intent, _check, _pending, _prepared = self.capture_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            directory, events = Path(tmp), []
            r.private_write(directory / 'token', b'token')
            r.private_write(directory / 'ready.json', r.json.dumps({'preboot_patch': True, 'baseline': config['baseline'], 'nonce': config['nonce']}).encode())
            for event in saved['facts']['owner_events']:
                r.debug_event(directory, config, event['event'], config['baseline'],
                    **({'bootplist_stage': event['bootplist_stage']} if event['event'] == 'bootplist_staged' else {}))
            def restore(*_args, **kwargs):
                self.assertEqual(kwargs['baseline_boot_argument_profile'], config['initial_boot_argument_profile'])
                events.append('restore')
                return copy.deepcopy(saved['facts'])
            def core(_directory, _config, _current, facts, _token):
                events.append('core_ack'); return facts
            def prime(*_args):
                events.append('prime_ack'); return saved['facts']['netdump_prime']
            def followup(_directory, _config, _current, facts, _token):
                self.assertEqual(facts['netdump_prime']['status'], 'verified')
                events.append('followup')
            def forbidden(*_args, **_kwargs): self.fail('capture used legacy completion or optional inventory')
            with patch.object(r, 'load_config', return_value=config), patch.object(r, 'boot_uuid', return_value=saved['scope']['debug_boot_uuid']), \
                 patch.object(r.recovery_bootplist, 'finish', restore), patch.object(r, 'publish_debug_core', core), \
                 patch.object(r, 'run_netdump_prime_once', prime), patch.object(r, 'followup_start', followup), \
                 patch.object(r.recovery_bootargs, 'observe_once', forbidden), patch.object(r, 'complete_recovery', forbidden), \
                 patch.object(r, 'followup_finish', forbidden):
                r.collect(directory)
            self.assertEqual(events, ['restore', 'core_ack', 'prime_ack', 'followup'])

    def test_capture_controller_uses_independent_result_and_closes_only_canonical_handoff(self):
        for outcome in ('fresh', 'unverified', 'failed', 'armed_then_lost', 'close_patch_unknown', 'close_get_unknown'):
            with self.subTest(outcome=outcome):
                config, _saved, intent, root_check, pending, _prepared = self.capture_fixture()
                scope = r.recovery_netdump_capture.CaptureScope.from_record(r.capture_intent_snapshot(root_check, pending, config['context'])['scope'])
                received = {'phase': 'failed', 'receiver_check_id': 13}
                if outcome == 'armed_then_lost': received = {'phase': 'armed', 'receiver_check_id': 13}
                elif outcome != 'failed':
                    stream = r.recovery_netdump_capture.FragmentStream('fragment')
                    body = ('panic(cpu 0 caller 0x1234): dtrace: panic action at probe pid123:helper:vz_nonce_' + config['nonce'] +
                            ':entry (ecb 0xabcd)\nKernel UUID: ' + (r.KERNEL_UUID if outcome in ('fresh', 'close_patch_unknown', 'close_get_unknown') else '0' * 36) + '\n').encode()
                    wire = r.recovery_netdump_capture.wire
                    stream.receive(wire.encode_wrq('fragment'))
                    stream.receive(wire.encode_paniclog_data(1, body, 'fragment', b'Y' * 9))
                    stream.finish('idle')
                    received = {'phase': 'captured', 'receiver_check_id': 13,
                                'result': r.recovery_netdump_capture.kernel_result(scope, stream)}
                public = {key: intent[key] for key in ('protocol', 'binding', 'nonce', 'baseline_boot_uuid', 'trigger',
                    'debug_boot', 'debug_source', 'after_debug_boot', 'cert_fingerprint')}
                public.update(phase='public_key', public_key='public-key-boundary')
                server = copy.deepcopy(root_check)
                server['output'] = {'summary': r.json.dumps(public)}
                calls, turns, reads, closes, close_gets = [], [], [], [], []
                def listing(*_args):
                    turns.append(True)
                    if len(turns) > 1: server.update(copy.deepcopy(root_check))
                    return copy.deepcopy(server)
                def api(method, _url, _token, payload=None, **_kwargs):
                    if method == 'PATCH':
                        phase = r.json.loads(payload['output']['summary'])['phase']
                        calls.append(phase)
                        server.update(copy.deepcopy(payload))
                        if phase == 'capture_controller_closed':
                            closes.append(payload['conclusion'])
                            if outcome == 'close_patch_unknown': raise TimeoutError('unknown_close_patch')
                    elif outcome == 'close_get_unknown' and closes and not close_gets:
                        close_gets.append(True)
                        raise TimeoutError('unknown_close_get')
                    if outcome in ('close_patch_unknown', 'close_get_unknown') and closes:
                        return copy.deepcopy(root_check)
                    return copy.deepcopy(server)
                def read(_ctx, _token, proof, actual_intent, root_id, _deadline):
                    self.assertEqual(root_id, 9)
                    self.assertEqual(actual_intent, intent)
                    self.assertEqual(proof, intent['debug_boot_facts']['netdump_prime']['proof'])
                    reads.append(True)
                    if outcome in ('close_patch_unknown', 'close_get_unknown') and len(reads) > 1:
                        raise RuntimeError('unexpected_outer_retry')
                    return None if outcome == 'armed_then_lost' and len(reads) > 1 else received
                def sleep(_seconds):
                    if outcome == 'armed_then_lost' and len(reads) > 1: raise RuntimeError('bounded_test_stop')
                output = io.StringIO()
                with patch.object(r, 'list_check', listing), patch.object(r, 'api', api), \
                     patch.object(r, 'encrypt_token', return_value=b'sealed'), patch.object(r.time, 'sleep', sleep), \
                     patch.object(r.signal, 'signal', lambda *_: None), patch.object(r.recovery_netdump, 'read_capture', read), \
                     contextlib.redirect_stdout(output):
                    if outcome == 'fresh': r.controller(config['context'], 'controller-token')
                    else:
                        with self.assertRaises((RuntimeError, TimeoutError)): r.controller(config['context'], 'controller-token')
                self.assertEqual(reads, [True, True] if outcome == 'armed_then_lost' else [True])
                self.assertEqual(calls, ['sealed_token', 'capture_controller_closed'])
                self.assertEqual(server['conclusion'], 'neutral' if outcome in ('fresh', 'close_patch_unknown', 'close_get_unknown') else 'failure')
                self.assertEqual(closes, ['neutral'] if outcome in ('fresh', 'close_patch_unknown', 'close_get_unknown') else ['failure'])
                book = r.json.loads(server['output']['summary'])['capture_bookkeeping']
                self.assertEqual(book['intent_sha256'], scope.intent_sha256)
                self.assertEqual(book['receiver_check_id'], 13)
                self.assertNotIn('panic(cpu', output.getvalue())

    def test_capture_controller_never_reseals_after_an_uncertain_seal_attempt(self):
        config, _saved, intent, check, _pending, _prepared = self.capture_fixture()
        public = {key: intent[key] for key in ('protocol', 'binding', 'nonce', 'baseline_boot_uuid', 'trigger',
            'debug_boot', 'debug_source', 'after_debug_boot', 'cert_fingerprint')}
        public.update(phase='public_key', public_key='public-key-boundary')
        check['output']['summary'] = r.json.dumps(public)
        patches, sleeps = [], []
        def api(method, *_args, **_kwargs):
            self.assertEqual(method, 'PATCH')
            patches.append(True)
            raise TimeoutError('unknown_seal_commit')
        def sleep(_seconds):
            sleeps.append(True)
            if len(sleeps) == 2: raise RuntimeError('bounded_test_stop')
        with patch.object(r, 'list_check', return_value=check), patch.object(r, 'api', api), \
             patch.object(r, 'encrypt_token', return_value=b'sealed'), patch.object(r.time, 'sleep', sleep), \
             patch.object(r.signal, 'signal', lambda *_: None):
            with self.assertRaises(RuntimeError): r.controller(config['context'], 'controller-token')
        self.assertEqual(patches, [True])


    def test_netdump_private_plan_binds_the_boot_mode_and_initial_profile(self):
        n = r.recovery_netdump
        ctx = {'run_id': '123', 'attempt': '1', 'sha': 'a' * 40, 'after_debug_boot': 'netdump-prime'}
        core, network = n.source_identity(r.__file__)
        profile = r.recovery_bootargs.boot_argument_profile('preempt=1')
        baseline = n.BootBaseline.from_profile('11111111-1111-1111-1111-111111111111', profile)
        offer = n.ReceiverOffer(r.binding(ctx), 'c' * 32, n.Endpoint('1.1.1.1', 10248), 43210,
                                'f' * 64, core, network, 'prime')
        settings = r.recovery_netdump_settings.NetdumpSettings('1.1.1.1', '192.168.64.1', 10248, 'b' * 16)
        plan = n.DiscoveryPlan(offer, 'b' * 64, n.Endpoint('8.8.8.8', 40000), '192.168.64.2', 'en0',
                               settings, n.HelloStats(True, True, 10), baseline)
        config = {'context': ctx, 'netdump_plan': plan.record(), 'nonce': plan.nonce,
                  'baseline': baseline.baseline_boot_uuid, 'cert_fingerprint': 'f' * 64,
                  'initial_boot_argument_profile': profile}
        self.assertEqual(r.netdump_plan(config), plan)
        for field, value in (('nonce', 'd' * 64), ('baseline', '22222222-2222-2222-2222-222222222222'),
                              ('cert_fingerprint', 'e' * 64), ('initial_boot_argument_profile', {'status': 'unavailable'})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.netdump_plan({**config, field: value})

    def test_netdump_prime_does_not_start_when_boot_restore_is_unproven(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            result = r.run_netdump_prime_once(directory, {'context': {'after_debug_boot': 'netdump-prime'}},
                                               'new', {}, 'token', 100)
            self.assertEqual(result, {'status': 'invalid'})
            self.assertEqual(list(directory.iterdir()), [])

    def test_netdump_prime_boot_success_requires_the_receiver_proof(self):
        ctx = {'run_id': '123', 'attempt': '1', 'sha': 'a' * 40, 'debug_source': 'bootplist',
               'debug_boot': True, 'trigger': 'reboot-quick', 'after_debug_boot': 'netdump-prime'}
        current = '22222222-2222-2222-2222-222222222222'
        facts = {'active_debug_mask': 0x22040, 'active_bootargs_status': 'observed_debug', 'current_boot_uuid': current,
                 'bootplist_restored': True, 'bootplist_file_states': {'data': 'staged', 'preboot': 'staged'},
                 'bootplist_restore': {name: {'bytes': True, 'metadata': True, 'timestamps': True} for name in ('data', 'preboot')}}
        pending = {'nonce': 'b' * 64, 'baseline_boot_uuid': '11111111-1111-1111-1111-111111111111',
                   'cert_fingerprint': 'c' * 64, 'check_id': 17}
        data = {'current_boot_uuid': current, 'debug_boot_facts': facts}
        self.assertTrue(r.debug_boot_proven(facts, 'bootplist', 0x22040))
        self.assertFalse(r.debug_lineage_matches(data, pending, ctx))
        facts['netdump_prime'] = {'status': 'verified', 'proof': {}}
        self.assertFalse(r.debug_lineage_matches(data, pending, ctx))

    def test_netdump_prime_is_a_certificate_bound_boot_control_without_panic(self):
        ctx = {'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
               'runner_environment': 'github-hosted', 'run_id': '123', 'attempt': '1', 'sha': 'a' * 40,
               'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'bootplist', 'after_debug_boot': 'netdump-prime'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.netdump_prime(ctx))
        self.assertEqual(r.expected_debug_mask(ctx), 0x22040)
        self.assertTrue(r.certificate_required(ctx))
        self.assertFalse(r.report_required(ctx))
        self.assertFalse(r.panic_followup(ctx))
        for change in ({'trigger': 'reboot'}, {'trigger': 'panic-control'}, {'debug_boot': False}, {'debug_source': 'nvram'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))

    def test_runtime_watch_identity_and_check_are_strict(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        check = {'id': 17, 'name': 'Runtime heartbeat 123', 'head_sha': 'a' * 40,
                 'external_id': r.runtime_watch_external(identity),
                 'app': {'id': 15368, 'slug': 'github-actions'},
                 'details_url': 'https://github.com/Code-Hex/vz-ci-test/runs/17'}
        self.assertTrue(r.runtime_watch_check(check, identity, 17))
        for change in ({'id': 18}, {'head_sha': 'b' * 40}, {'external_id': 'other'},
                       {'name': 'Runner recovery 123'}, {'app': {'id': 1, 'slug': 'github-actions'}}):
            self.assertFalse(r.runtime_watch_check({**check, **change}, identity, 17))
        with self.assertRaises(ValueError):
            r.runtime_watch_identity(config, {**saved['scope'], 'debug_boot_uuid': config['baseline']}, 'f' * 64)

    def test_runtime_watch_release_requires_exact_trigger(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        release = {'scope': saved['scope'], 'helper_sha256': 'f' * 64,
                   'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        raw = r.json.dumps(release).encode()
        self.assertEqual(r.runtime_watch_release(raw, raw, identity), r.hashlib.sha256(raw).hexdigest())
        for change in ({'ready': False}, {'helper_pid': True}, {'tracer_pid': 123},
                       {'helper_sha256': '0' * 64}, {'extra': 'private'},
                       {'scope': {**saved['scope'], 'nonce': '0' * 64}}):
            with self.assertRaises(ValueError):
                r.runtime_watch_release(r.json.dumps({**release, **change}).encode(), raw, identity)
        with self.assertRaises(ValueError):
            r.runtime_watch_release(raw, b'{}', identity)

    def test_runtime_watch_stage_needs_local_release_evidence(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'panic-control').mkdir()
            before = ('before_release', None)
            self.assertEqual(r.runtime_watch_stage(directory, identity, before), before)
            record = {'scope': saved['scope'], 'helper_sha256': 'f' * 64,
                      'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
            raw = r.json.dumps(record).encode()
            r.private_write(directory / 'panic-control' / 'release-attempt.json', raw)
            r.private_write(directory / 'panic-followup-trigger.json', raw)
            observed = r.runtime_watch_stage(directory, identity, before)
            self.assertEqual(observed, ('release_observed', r.hashlib.sha256(raw).hexdigest()))
            (directory / 'panic-control' / 'release-attempt.json').unlink()
            self.assertEqual(r.runtime_watch_stage(directory, identity, observed), observed)
            r.private_write(directory / 'panic-control' / 'release-attempt.json', b'{}')
            self.assertEqual(r.runtime_watch_stage(directory, identity, before), ('invalid', None))

    def test_runtime_watch_ready_requires_same_live_child_and_budget(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        receipt = {'identity': identity, 'check_id': 17, 'pid': 123, 'started_monotonic': 10.0,
                   'deadline_monotonic': 130.0, 'acknowledged': True}
        self.assertEqual(r.runtime_watch_ready(receipt, identity, 123, 9.0, 20.0), 130.0)
        for change in ({'pid': 456}, {'acknowledged': False}, {'deadline_monotonic': float('inf')},
                       {'check_id': True}, {'identity': {**identity, 'helper_sha256': '0' * 64}}):
            with self.assertRaises(ValueError):
                r.runtime_watch_ready({**receipt, **change}, identity, 123, 9.0, 20.0)
        with self.assertRaises(ValueError):
            r.runtime_watch_ready(receipt, identity, 123, 9.0, 71.0)

    def test_runtime_watch_ready_accepts_fractional_producer_deadlines(self):
        config, saved, _ = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        for started in (17.000000001, 27.123456789, 42.123456789, 72.123456789, 1024.0001):
            receipt = {'identity': identity, 'check_id': 17, 'pid': 123, 'started_monotonic': started,
                       'deadline_monotonic': started + 120, 'acknowledged': True}
            with self.subTest(started=started):
                self.assertEqual(r.runtime_watch_ready(receipt, identity, 123, started - .1, started + .1), started + 120)

    def test_runtime_watch_ready_is_published_complete_and_never_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt = {'acknowledged': True, 'identity': {'fixture': 'complete'}}
            real_write = r.private_write
            def write(path, data):
                self.assertIn(path.name, ('runtime-watch-ready.pending.json', 'runtime-watch-ready.claim.json'))
                self.assertFalse((directory / 'runtime-watch-ready.json').exists())
                real_write(path, data)
            with patch.object(r, 'private_write', write):
                r.publish_runtime_watch_ready(directory, receipt)
            target = directory / 'runtime-watch-ready.json'
            self.assertEqual(r.json.loads(target.read_bytes()), receipt)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse((directory / 'runtime-watch-ready.pending.json').exists())
            with self.assertRaises(ValueError):
                r.publish_runtime_watch_ready(directory, {'replacement': True})
            self.assertEqual(r.json.loads(target.read_bytes()), receipt)

    def test_runtime_watch_retries_an_incomplete_release_observation(self):
        config, saved, _ = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        release = {'scope': saved['scope'], 'helper_sha256': 'f' * 64, 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        raw = r.json.dumps(release).encode()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'panic-control').mkdir()
            path = directory / 'panic-control' / 'release-attempt.json'
            r.private_write(path, b'{')
            r.private_write(directory / 'panic-followup-trigger.json', raw)
            partial = r.runtime_watch_stage(directory, identity, ('before_release', None))
            self.assertEqual(partial, ('invalid', None))
            path.write_bytes(raw)
            self.assertEqual(r.runtime_watch_stage(directory, identity, partial), ('release_observed', r.hashlib.sha256(raw).hexdigest()))

    def test_runtime_watch_reaper_waits_for_a_real_child(self):
        child = subprocess.Popen([r.sys.executable, '-c', 'pass'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        waiter = r.reap_runtime_watch(child)
        waiter.join(3)
        self.assertTrue(waiter.daemon)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(child.returncode, 0)

    def test_runtime_watch_failure_prevents_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            events = []
            def prepare(*_args, **_kwargs):
                (directory / 'panic-control').mkdir()
                return {'helper_sha256': 'f' * 64}
            def unavailable(*_args):
                events.append('watch_failed')
                raise TimeoutError('not ready')
            with patch.object(r.recovery_panic_control, 'prepare', prepare), \
                    patch.object(r, 'publish_followup', lambda *_a: events.append('prepared_ack')), \
                    patch.object(r, 'start_runtime_watch', unavailable), \
                    patch.object(r.recovery_panic_control, 'fire', lambda *_a: self.fail('watch failure reached fire')), \
                    patch.object(r, 'complete_recovery', lambda *_a: events.append('reported')):
                r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertEqual(events, ['prepared_ack', 'watch_failed', 'reported'])
            self.assertFalse((directory / 'panic-followup-trigger.json').exists())

    def test_runtime_watch_budget_is_checked_after_intent_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            events = []
            def prepare(*_args, **_kwargs):
                (directory / 'panic-control').mkdir()
                return {'helper_sha256': 'f' * 64}
            def publish(_d, _c, _t, summary, _title):
                events.append(summary['phase'])
            def alive(_watch, minimum=60):
                self.assertIn(minimum, (60, 30))
                return 'panic_intent' not in events
            def fire(_d, scope, prepared, _save, _sync, on_ready, _boot, **_kwargs):
                trigger = {'scope': scope, 'helper_sha256': prepared['helper_sha256'],
                           'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
                self.assertFalse(on_ready(trigger))
                self.assertFalse((directory / 'panic-control' / 'release-attempt.json').exists())
                events.append('not_released')
                return {'phase': 'not_released'}
            with patch.object(r.recovery_panic_control, 'prepare', prepare), patch.object(r.recovery_panic_control, 'fire', fire), \
                    patch.object(r, 'publish_followup', publish), patch.object(r, 'start_runtime_watch', lambda *_a: object()), \
                    patch.object(r, 'runtime_watch_alive', alive), patch.object(r, 'boot_uuid', lambda: saved['scope']['debug_boot_uuid']), \
                    patch.object(r, 'complete_recovery', lambda *_a: events.append('reported')):
                r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertEqual(events, ['panic_prepared', 'panic_intent', 'not_released', 'reported'])

    def test_boot_argument_profiles_keep_first_scoped_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            config['initial_boot_argument_profile'] = r.recovery_bootargs.boot_argument_profile('alpha=1 beta=2')
            current = saved['scope']['debug_boot_uuid']
            with patch.object(r, 'observe_boot_argument_profile', lambda: r.recovery_bootargs.boot_argument_profile('alpha=1 debug=0x102000 beta=2')):
                first = r.postboot_argument_profiles(directory, config, current)
            self.assertIs(first['nondebug_equal'], True)
            with patch.object(r, 'observe_boot_argument_profile', lambda: self.fail('observation was repeated')):
                self.assertEqual(r.postboot_argument_profiles(directory, config, current), first)
            self.assertEqual(r.postboot_argument_profiles(directory, config, 'C' * 8 + '-CCCC-CCCC-CCCC-' + 'C' * 12)['postboot'], {'status': 'invalid'})
            self.assertNotIn('alpha', (directory / 'boot-argument-observation.json').read_text())

    def test_boot_argument_observation_failure_does_not_claim_equality(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            config['initial_boot_argument_profile'] = r.recovery_bootargs.boot_argument_profile('alpha=1')
            with patch.object(r, 'observe_boot_argument_profile', lambda: {'status': 'unavailable'}):
                result = r.postboot_argument_profiles(directory, config, saved['scope']['debug_boot_uuid'])
            self.assertIsNone(result['nondebug_equal'])
            self.assertEqual(result['postboot'], {'status': 'unavailable'})
            (directory / 'boot-argument-observation.json').write_text('{broken')
            self.assertEqual(r.postboot_argument_profiles(directory, config, saved['scope']['debug_boot_uuid'])['postboot'], {'status': 'invalid'})

    def test_boot_argument_storage_failure_still_restores_and_acknowledges(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            current = saved['scope']['debug_boot_uuid']
            config['debug_boot'] = True
            config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
            r.private_write(directory / 'token', b'synthetic-token')
            r.private_write(directory / 'ready.json', r.json.dumps({'baseline': config['baseline'], 'nonce': config['nonce'], 'preboot_patch': True}).encode())
            original_write = r.private_write
            events = []
            def write(path, data):
                if path.name in ('boot-argument-observation.json', 'nvram-paniclog-control.json'):
                    raise OSError('synthetic storage failure')
                original_write(path, data)
            def finish(*_args, **_kwargs):
                events.append('restore')
                return dict(saved['facts'])
            def core(_directory, _config, _current, facts, _token):
                self.assertEqual(facts['boot_argument_profiles']['postboot'], {'status': 'invalid'})
                self.assertIsNone(facts['boot_argument_profiles']['nondebug_equal'])
                self.assertEqual(facts['nvram_paniclog_control'], {'status': 'invalid'})
                self.assertFalse(r.nvram_off_control_proven(facts))
                events.append('ack')
                return facts
            with patch.object(r, 'load_config', lambda _: config), patch.object(r, 'boot_uuid', lambda: current), \
                    patch.object(r, 'observe_boot_argument_profile', lambda: {'status': 'unavailable'}), \
                    patch.object(r.recovery_bootargs.MacPlatform, 'active', lambda _: 'alpha=1 nvram_paniclog=0 debug=0x102000'), \
                    patch.object(r, 'private_write', write), patch.object(r.recovery_bootplist, 'finish', finish), \
                    patch.object(r, 'publish_debug_core', core), patch.object(r, 'followup_start', lambda *_, **_kwargs: events.append('followup')):
                r.collect(directory)
            self.assertEqual(events, ['restore', 'ack', 'followup'])

    def test_boot_argument_profile_boundary_rejects_raw_and_invalid_scalars(self):
        valid = r.recovery_bootargs.boot_argument_profile('alpha=1')
        for extra in ({'raw': 'private argument'}, {'debug_mask': True}, {'nondebug_token_count': True},
                      {'nondebug_token_count': -1}, {'nondebug_sha256': 'private argument'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                r.checked_boot_argument_profile({**valid, **extra})

    def test_runtime_watch_ready_timeout_reaps_its_own_child_before_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _ = self.followup_fixture()
            config['python'] = str(Path(r.sys.executable).resolve())
            (directory / 'panic-control').mkdir()
            child = subprocess.Popen([r.sys.executable, '-c', 'import time; time.sleep(60)'])
            try:
                with patch.object(r, 'runtime_watch_executable_matches', lambda *_: True), \
                        patch.object(r.subprocess, 'Popen', lambda *_args, **_kwargs: child), \
                        patch.object(r.time, 'monotonic', side_effect=[0, 26]):
                    with self.assertRaises(TimeoutError):
                        r.start_runtime_watch(directory, config, saved['scope'], {'helper_sha256': 'f' * 64})
                self.assertIsNotNone(child.poll())
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait()

    def test_runtime_watch_accepts_the_same_copied_script_through_a_directory_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / 'real'
            real.mkdir()
            (real / 'recovery.py').write_text('same script')
            alias = Path(tmp) / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            python = str(Path(r.sys.executable).resolve())
            with patch.object(r, '__file__', str(real / 'recovery.py')):
                self.assertTrue(r.runtime_watch_executable_matches(alias, python))
                self.assertFalse(r.runtime_watch_executable_matches(Path(tmp), python))
                self.assertFalse(r.runtime_watch_executable_matches(alias, '/unrelated/python'))

    def test_nvram_off_mode_is_bound_and_requires_the_exact_control_token(self):
        config, saved, _ = self.followup_fixture()
        ctx = {**config['context'], 'after_debug_boot': 'panic-nonce-nvram-off', 'actions': 'true', 'repo': r.REPO,
               'ref': 'refs/heads/main', 'event': 'workflow_dispatch', 'runner_environment': 'github-hosted'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.panic_followup(ctx))
        self.assertEqual(r.expected_debug_mask(ctx), 0x102000)
        initial = r.recovery_bootargs.boot_argument_profile('alpha=1 beta=2')
        active = 'alpha=1 beta=2 nvram_paniclog=0 debug=0x102000'
        control = r.parse_nvram_off_control(active)
        facts = {**saved['facts'], 'boot_argument_profiles': {'initial': initial,
                 'postboot': r.recovery_bootargs.boot_argument_profile(active)}, 'nvram_paniclog_control': control}
        self.assertTrue(r.nvram_off_control_proven(facts))
        for raw in ('alpha=1 beta=2 debug=0x102000', 'alpha=1 beta=2 -nvram_paniclog=0 debug=0x102000',
                    'alpha=1 beta=2 nvram_paniclog=0 nvram_paniclog=0 debug=0x102000',
                    'alpha=1 beta=2 nvram_paniclog=1 debug=0x102000'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                r.parse_nvram_off_control(raw)
        for changed in ('beta=2 alpha=1 nvram_paniclog=0 debug=0x102000',
                        'alpha=1 beta=2 extra=1 nvram_paniclog=0 debug=0x102000'):
            changed_control = r.parse_nvram_off_control(changed)
            self.assertFalse(r.nvram_off_control_proven({**facts, 'nvram_paniclog_control': changed_control,
                'boot_argument_profiles': {'initial': initial, 'postboot': changed_control['full_profile']}}))
        for bad in ({'status': 'unavailable'}, {'status': 'invalid'}, {**control, 'raw': 'private'}):
            self.assertFalse(r.nvram_off_control_proven({**facts, 'nvram_paniclog_control': bad}))

    def test_nvram_off_observation_is_immutable_and_bound_to_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _ = self.followup_fixture()
            config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
            current = saved['scope']['debug_boot_uuid']
            with patch.object(r.recovery_bootargs.MacPlatform, 'active', lambda _: 'alpha=1 nvram_paniclog=0 debug=0x102000'):
                first = r.postboot_paniclog_control(directory, config, current)
            self.assertEqual(first['status'], 'observed')
            with patch.object(r.recovery_bootargs.MacPlatform, 'active', lambda _: self.fail('repeated control read')):
                self.assertEqual(r.postboot_paniclog_control(directory, config, current), first)
            config['context']['after_debug_boot'] = 'panic-nonce'
            self.assertEqual(r.postboot_paniclog_control(directory, config, current), {'status': 'invalid'})

    def test_nvram_off_proof_is_required_by_replay_and_controller(self):
        config, saved, b3 = self.followup_fixture()
        config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
        initial = r.recovery_bootargs.boot_argument_profile('alpha=1')
        control = r.parse_nvram_off_control('alpha=1 nvram_paniclog=0 debug=0x102000')
        facts = {**saved['facts'], 'nvram_paniclog_control': control,
                 'boot_argument_profiles': {'initial': initial, 'postboot': control['full_profile']}}
        trigger = {'scope': saved['scope'], 'helper_sha256': 'f' * 64, 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        pending = {'nonce': config['nonce'], 'baseline_boot_uuid': config['baseline']}
        data = {'debug_boot_facts': facts, 'debug_boot_uuid': saved['scope']['debug_boot_uuid'],
                'current_boot_uuid': b3, 'panic_trigger': trigger}
        self.assertTrue(r.debug_lineage_matches(data, pending, config['context']))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            target = directory / 'panic-followup-debug.json'
            target.write_text(r.json.dumps({'scope': saved['scope'], 'facts': facts}))
            self.assertEqual(r.read_followup_debug(directory, config)['facts'], facts)
            missing = {k: v for k, v in facts.items() if k != 'nvram_paniclog_control'}
            target.write_text(r.json.dumps({'scope': saved['scope'], 'facts': missing}))
            with self.assertRaises(ValueError):
                r.read_followup_debug(directory, config)
            self.assertFalse(r.debug_lineage_matches({**data, 'debug_boot_facts': missing}, pending, config['context']))

    def test_nvram_off_missing_proof_prevents_prepare_and_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _ = self.followup_fixture()
            config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
            completed = []
            def forbidden(*_args, **_kwargs):
                self.fail('unproven NVRAM logging control reached prepare or fire')
            with patch.object(r.recovery_panic_control, 'prepare', forbidden), patch.object(r.recovery_panic_control, 'fire', forbidden), \
                    patch.object(r, 'complete_recovery', lambda *_a: completed.append(True)):
                r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertEqual(completed, [True])
            self.assertFalse((directory / 'panic-control' / 'intent.json').exists())

    def test_debug_source_context_is_explicit_and_bound(self):
        base = {'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
                'runner_environment': 'github-hosted', 'run_id': '123', 'attempt': '1', 'sha': 'a' * 40,
                'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'nvram'}
        self.assertTrue(r.valid_context(base, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.valid_context({**base, 'debug_source': 'bootplist'}, 'Darwin', 'x86_64', r.KERNEL_UUID))
        missing = {key: value for key, value in base.items() if key != 'debug_source'}
        for invalid in (missing, {**base, 'debug_source': 'unknown'},
                        {**base, 'debug_source': 'bootplist', 'debug_boot': False},
                        {**base, 'debug_source': 'bootplist', 'trigger': 'reboot'}):
            self.assertFalse(r.valid_context(invalid, 'Darwin', 'x86_64', r.KERNEL_UUID))
        data = {'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'nvram'}
        self.assertTrue(r.mode_matches(data, {}, base))
        self.assertFalse(r.mode_matches({key: value for key, value in data.items() if key != 'debug_source'}, {}, base))
        self.assertFalse(r.mode_matches({**data, 'debug_source': 'bootplist'}, {}, base))

    def cleanup_cli(self, *, check_id="126520221299", token="test-job-token", status="in_progress", system="Linux", repo="Code-Hex/vz-ci-test"):
        old_sha = "a" * 40
        check = {"id": 126520221299, "name": "Runner recovery 41814026408", "head_sha": old_sha,
                 "external_id": "41814026408/1/" + old_sha, "app": {"slug": "github-actions", "id": 15368},
                 "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/126520221299", "status": status}
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": repo, "GITHUB_RUN_ID": "999",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b" * 40, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
               "GITHUB_TOKEN": token, "RECOVERY_CLEANUP_CHECK_ID": check_id}
        calls = []

        def api(method, url, credential, payload=None):
            self.assertEqual(credential, token)
            self.assertEqual(url, r.CHECKS + "/126520221299")
            calls.append((method, payload))
            if method == "GET":
                return check
            self.assertEqual(method, "PATCH")
            return {}

        def command(command):
            return {("/usr/bin/uname", "-s"): system, ("/usr/bin/uname", "-m"): "x86_64",
                    ("/usr/sbin/sysctl", "-n", "kern.uuid"): r.KERNEL_UUID}[tuple(command)]

        def forbidden(*_args, **_kwargs):
            self.fail("cleanup entered controller or sudo path")

        with patch.dict(os.environ, env, clear=True), patch.object(r.sys, "argv", ["reboot-recovery.py", "cleanup"]), \
                patch.object(r, "api", api), patch.object(r, "command_output", command), \
                patch.object(r, "controller", forbidden), patch.object(r, "sudo_call", forbidden), \
                contextlib.redirect_stdout(io.StringIO()):
            r.main()
        return calls

    def test_cleanup_cli_only_cancels_verified_old_check(self):
        self.assertEqual(self.cleanup_cli(), [("GET", None), ("PATCH", {
            "status": "completed", "conclusion": "cancelled",
            "output": {"title": "Prior recovery attempt cancelled", "summary": "Superseded recovery attempt."}})])

    def test_cleanup_cli_completed_check_needs_no_patch(self):
        self.assertEqual(self.cleanup_cli(status="completed"), [("GET", None)])

    def test_cleanup_cli_requires_token_id_and_linux_context(self):
        for options in ({"token": ""}, {"check_id": ""}, {"check_id": "../126520221299"},
                        {"system": "Darwin"}, {"repo": "other"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.cleanup_cli(**options)

    def test_guard(self):
        ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "2",
               "sha": "a" * 40, "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        for key, value in [("actions", "false"), ("repo", "other"), ("run_id", "../1"),
                           ("attempt", "0"), ("sha", "bad"), ("event", "push")]:
            self.assertFalse(r.valid_context(dict(ctx, **{key: value}), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(ctx, "Darwin", "arm64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(ctx, "Darwin", "x86_64", "bad"))

    def test_force_preflight_errors_are_whitelisted(self):
        self.assertEqual(r.safe_force_preflight_error('secret\n{"event":"force_reset_guard_failed","token":"secret"}'), {"event": "force_reset_guard_failed"})
        self.assertEqual(r.safe_force_preflight_error('{"event":"force_reset_symbol_unavailable"}'), {"event": "force_reset_symbol_unavailable"})
        self.assertIsNone(r.safe_force_preflight_error('{"event":"secret"}'))
        self.assertIsNone(r.safe_force_preflight_error('{"event":[]}'))

    def test_force_return_diagnostic_is_numeric_and_redacted(self):
        text = 'secret\n{"event":"force_reset_unexpected_return","result":-1,"errno":1,"token":"secret"}\n'
        self.assertEqual(r.safe_force_return(text), {"event": "force_reset_unexpected_return", "result": -1, "errno": 1})
        self.assertIsNone(r.safe_force_return('{"event":"force_reset_unexpected_return","result":"secret","errno":1}'))
        self.assertIsNone(r.safe_force_return('secret'))

    def test_quick_trigger_and_return_facts_are_bound_and_redacted(self):
        ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1", "sha": "a" * 40,
               "ref": "refs/heads/main", "event": "workflow_dispatch", "runner_environment": "github-hosted",
               "trigger": "reboot-quick", "debug_boot": False}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, debug_boot=True), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.panic_mode(ctx))
        fact = r.safe_quick_return('raw-secret\n{"event":"quick_reboot_unexpected_return","result":-1,"errno":1,"token":"raw-secret"}')
        self.assertEqual(fact, {"event": "quick_reboot_unexpected_return", "result": -1, "errno": 1})
        self.assertIsNone(r.safe_quick_return('{"event":"quick_reboot_unexpected_return","result":true,"errno":1}'))
        self.assertFalse(r.mode_matches({"debug_source": "nvram", "trigger": "reboot"}, {}, ctx))
        pending = {"nonce": "n", "baseline_boot_uuid": "old"}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx),
                "nonce": "n", "baseline_boot_uuid": "old", "current_boot_uuid": "new", "trigger": "reboot-quick"}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, phase="quick_prepared"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, phase="quick_intent"), pending, ctx))

    def test_quick_main_only_routes_to_root_rpc(self):
        calls = []
        def sudo(operation, *_args, **kwargs):
            calls.append((operation, kwargs["timeout"]))
            return ""
        def forbidden(*_args, **_kwargs):
            self.fail("quick trigger used the normal reboot path")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "trigger"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot-quick", "debug_boot": False}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, [("quick-execute-root", 90)])

    def test_debug_quick_parent_only_requests_launchd_owner(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return ""
        def tick(seconds):
            calls.append('wait')
            if calls.count('wait')==4:raise KeyboardInterrupt()
        def forbidden(*_args, **_kwargs):
            self.fail("debug quick parent directly executed reset")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "trigger"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot-quick", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                patch.object(r.time, "sleep", tick), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root", "wait", "wait", "wait", "wait"])

    def test_quick_prepared_ack_precedes_execute_and_return_completes_failure(self):
        for acknowledged in (True, False):
            with self.subTest(acknowledged=acknowledged), tempfile.TemporaryDirectory() as tmp:
                directory, events, output = Path(tmp), [], io.StringIO()
                ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1", "sha": "a" * 40,
                       "ref": "refs/heads/main", "event": "workflow_dispatch", "runner_environment": "github-hosted",
                       "trigger": "reboot-quick", "debug_boot": False}
                helper = directory / "reboot-quick"
                helper.write_bytes(b"synthetic helper")
                config = {"context": ctx, "baseline": "old", "nonce": "n", "check_id": 9, "cert_fingerprint": "",
                          "helper_sha256": r.hashlib.sha256(helper.read_bytes()).hexdigest()}
                r.private_write(directory / "token", b"private-token")
                initial = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "phase": "armed", "binding": r.binding(ctx), "nonce": "n",
                           "baseline_boot_uuid": "old", "trigger": "reboot-quick", "debug_boot": False, "cert_fingerprint": ""}
                check = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                         "app": {"id": 15368, "slug": "github-actions"}, "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                         "status": "in_progress", "output": {"summary": r.json.dumps(initial)}}
                def api(method, _url, token, payload=None, **_kwargs):
                    self.assertEqual(token, "private-token")
                    if method == "GET":
                        events.append("ack" if "prepared" in events else "get")
                        result = dict(check)
                        if "prepared" in events and not acknowledged:
                            result["status"] = "completed"
                        return result
                    check.update(payload)
                    events.append("failed" if payload.get("status") == "completed" else "prepared")
                    return check
                def run(command, **kwargs):
                    self.assertEqual(command, [str(helper), "preflight"])
                    self.assertTrue((directory / "quick-trigger.json").exists())
                    self.assertEqual(kwargs["env"]["RECOVERY_TRIGGER"], "reboot-quick")
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    events.append("preflight")
                    return subprocess.CompletedProcess(command, 0, '{"event":"quick_reboot_preflight","flags":1024,"permission_verified":false}', '')
                class Child:
                    returncode = 70
                    pid = 1234
                    def communicate(self, timeout):
                        return ('raw-secret\n{"event":"quick_reboot_unexpected_return","result":-1,"errno":1}', '')
                def popen(command, **kwargs):
                    self.assertEqual(command, [str(helper), "execute"])
                    self.assertEqual(events[-1], "ack")
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    events.append("execute")
                    return Child()
                with patch.object(r, "root_only", lambda: None), patch.object(r, "require_context", lambda *_: None), \
                        patch.object(r, "root_dir", lambda _: directory), patch.object(r, "load_config", lambda _: config), \
                        patch.object(r, "verify_root", lambda _: None), patch.object(r, "boot_uuid", lambda: "old"), \
                        patch.object(r.os, "sync", lambda: events.append("sync")), patch.object(r.subprocess, "run", run), \
                        patch.object(r.subprocess, "Popen", popen), patch.object(r, "api", api), contextlib.redirect_stdout(output):
                    with self.assertRaises((RuntimeError, ValueError)):
                        r.quick_execute_root({"context": ctx})
                self.assertEqual(events[:2], ["sync", "preflight"])
                self.assertNotIn("raw-secret", output.getvalue())
                if acknowledged:
                    self.assertEqual(events[-2:], ["execute", "failed"])
                    self.assertEqual(check["conclusion"], "failure")
                else:
                    self.assertNotIn("execute", events)

    def test_root_error_kind_is_whitelisted(self):
        self.assertEqual(r.root_error_kind('noise SECRET\n{"event":"recovery_error","kind":"ValueError"}\n'), "ValueError")
        self.assertEqual(r.root_error_kind('{"event":"recovery_error","kind":"SECRET"}'), "unknown")
        self.assertEqual(r.root_error_kind('{"event":"other","kind":"ValueError"}'), "unknown")
        self.assertEqual(r.root_error_kind('unstructured SECRET'), "unknown")

    def test_force_reset_marker_and_guard(self):
        ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1",
               "sha": "a" * 40, "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted", "trigger": "panic-force-reset"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, trigger="panic-control"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, trigger="reboot"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(dict(ctx, trigger="unknown"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertEqual(r.force_marker(ctx, "b" * 64), "vz-force-reset:123:1:" + "b" * 64)
        with self.assertRaises(ValueError):
            r.force_marker(ctx, "not-a-nonce")

    def test_only_changed_nonempty_boot_is_recovery(self):
        self.assertFalse(r.reboot_observed("abc", "abc"))
        self.assertFalse(r.reboot_observed("abc", ""))
        self.assertTrue(r.reboot_observed("abc", "def"))

    def test_debug_boot_request_accepts_only_normal_reset_triggers(self):
        self.assertTrue(r.recovery_bootargs.requested("1", "reboot"))
        self.assertTrue(r.recovery_bootargs.requested("1", "reboot-quick"))
        self.assertFalse(r.recovery_bootargs.requested("", "reboot"))
        for value, trigger in (("true", "reboot"), ("1", "panic-control"), ("1", "panic-force-reset")):
            with self.assertRaises(ValueError):
                r.recovery_bootargs.requested(value, trigger)

    def test_debug_boot_proof_requires_mask_restore_and_mode_binding(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True}
        pending = {"nonce": "n", "baseline_boot_uuid": "old"}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx),
                "nonce": "n", "baseline_boot_uuid": "old", "current_boot_uuid": "new", "debug_boot": True,
                "debug_boot_facts": {"active_debug_mask": 0x2000, "active_bootargs_status": "observed_debug", "nvram_restored": True,
                                     "current_boot_uuid": "new",
                                     "debugger_count": None, "nic_inventory_status": "unsupported"}}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        core = dict(data, phase="boot_core")
        self.assertFalse(r.boot_proof_matches(core, pending, ctx))
        for facts in ({}, {"active_debug_mask": 0x2000, "nvram_restored": False},
                      {"active_debug_mask": 0x400, "nvram_restored": True},
                      {"active_debug_mask": 0x2000, "active_bootargs_status": "invalid", "nvram_restored": True}):
            self.assertFalse(r.boot_proof_matches(dict(data, debug_boot_facts=facts), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, debug_boot=False), pending, ctx))
        self.assertFalse(r.boot_proof_matches(data, pending, dict(ctx, debug_boot=False)))
        self.assertFalse(r.boot_proof_matches(dict(data, current_boot_uuid="another"), pending, ctx))
        quick_ctx = dict(ctx, trigger="reboot-quick")
        quick_data = dict(data, trigger="reboot-quick")
        self.assertTrue(r.boot_proof_matches(quick_data, pending, quick_ctx))
        self.assertFalse(r.boot_proof_matches(data, pending, quick_ctx))
        self.assertFalse(r.boot_proof_matches(quick_data, pending, ctx))

    def test_debug_parent_shutdown_cannot_restore_or_reboot(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            if operation == "verify-root":
                return "ready"
            self.assertEqual(operation, "debug-request-root")
            raise KeyboardInterrupt()
        def forbidden(*_args, **_kwargs):
            self.fail("runner parent performed debug mutation or reboot")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root"])

    def test_debug_parent_waits_after_request_without_mutation(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return "ready"
        def tick(seconds):
            calls.append('wait')
            if calls.count('wait')==4:raise KeyboardInterrupt()
        def forbidden(*_args, **_kwargs):
            self.fail("runner parent mutated debug state")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                patch.object(r.time, "sleep", tick), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root", "wait", "wait", "wait", "wait"])

    def test_bootplist_proof_requires_file_restoration(self):
        facts = {"active_debug_mask": 0x2000, "active_bootargs_status": "observed_debug",
                 "nvram_restored": True}
        self.assertTrue(r.debug_boot_proven(facts, "nvram"))
        self.assertFalse(r.debug_boot_proven(facts, "bootplist"))
        facts.pop("nvram_restored")
        facts.update({"bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "original"},
                      "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}})
        self.assertTrue(r.debug_boot_proven(facts, "bootplist"))
        self.assertFalse(r.debug_boot_proven(facts, "nvram"))
        for invalid in ({"active_debug_mask": None}, {"bootplist_restored": False},
                        {"bootplist_file_states": {"data": "staged", "preboot": "other"}},
                        {"bootplist_restore": {}}):
            self.assertFalse(r.debug_boot_proven({**facts, **invalid}, "bootplist"))

    def test_bootplist_owner_ack_precedes_single_reboot_without_nvram(self):
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update(debug_source="bootplist", trigger="reboot-quick")
                events = []
                def stage(*_args, **_kwargs):
                    events.append("stage")
                    if uncertain:
                        raise r.recovery_bootplist.WriteUncertain()
                    return {"data": "staged", "preboot": "staged", "metadata_preserved": True}
                def prepared(*_args):
                    events.append("prepared")
                    return {"phase": "quick_prepared"}
                def acknowledged(_directory, _config, value):
                    self.assertTrue((directory / "debug-reboot-intent.json").exists())
                    evidence = r.read_debug_event(directory, config, "bootplist_staged")
                    self.assertTrue(evidence["bootplist_stage"]["metadata_preserved"])
                    events.append("ack")
                    return value
                def reboot(*_args, **_kwargs):
                    events.append("reboot")
                    return {"returncode": 1}
                def forbidden(*_args, **_kwargs):
                    self.fail("unexpected NVRAM operation or uncertain rollback")
                with patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                        patch.object(r.recovery_bootargs, "stage", forbidden), \
                        patch.object(r.recovery_bootargs, "rollback", forbidden), \
                        patch.object(r.recovery_bootplist, "stage", stage), \
                        patch.object(r.recovery_bootplist, "rollback", forbidden), \
                        patch.object(r, "native_force_sync", forbidden), \
                        patch.object(r, "quick_prepare", prepared), \
                        patch.object(r, "quick_intent_ack", acknowledged), \
                        patch.object(r, "quick_reboot_child", reboot):
                    r.debug_owner(directory, config, "old")
                    r.debug_owner(directory, config, "old")
                self.assertEqual(events, ["stage"] if uncertain else ["stage", "prepared", "ack", "reboot"])
                self.assertEqual((directory / "debug-reboot-intent.json").exists(), not uncertain)

    def test_bootplist_collection_restores_before_ack_and_inventory(self):
        for restored in (True, False):
            with self.subTest(restored=restored), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update(debug_source="bootplist", trigger="reboot-quick")
                config["check_id"] = 9
                r.private_write(directory / "token", b"synthetic-token")
                r.private_write(directory / "ready.json", r.json.dumps({"baseline": "old", "nonce": config["nonce"], "preboot_patch": True}).encode())
                events = []
                def finish(*_args, **_kwargs):
                    events.append("restore")
                    if not restored:
                        raise r.recovery_bootplist.WriteUncertain()
                    return {"current_boot_uuid": "new", "active_debug_mask": 0x2000, "active_bootargs_status": "observed_debug",
                            "bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "staged"},
                            "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}}
                def core(_directory, _config, _current, facts, _token):
                    self.assertNotIn("nvram_restored", facts)
                    self.assertEqual(facts["bootplist_restored"], restored)
                    events.append("ack")
                    return facts
                def inventory(*_args, **_kwargs):
                    events.append("inventory")
                    return {}
                def api(_method, _url, _token, payload, **_kwargs):
                    events.append(payload["conclusion"])
                    error = r.urllib.error.HTTPError("https://api.github.com", 401, "test refusal", {}, None)
                    self.addCleanup(error.close)
                    raise error
                def forbidden(*_args, **_kwargs):
                    self.fail("file collection used NVRAM restoration")
                with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: "new"), \
                        patch.object(r.recovery_bootplist, "finish", finish), patch.object(r.recovery_bootargs, "finish", forbidden), \
                        patch.object(r, "publish_debug_core", core), patch.object(r.recovery_bootargs, "observe_once", inventory), \
                        patch.object(r, "api", api):
                    r.collect(directory)
                self.assertEqual(events, ["restore", "ack", "inventory", "success"] if restored else ["restore", "ack", "failure"])

    def test_panic_followup_context_is_restricted_to_debug_bootplist(self):
        ctx = {"actions": "true", "repo": "Code-Hex/vz-ci-test", "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted", "run_id": "123", "attempt": "1", "sha": "a" * 40,
               "trigger": "reboot-quick", "debug_boot": True, "debug_source": "bootplist", "after_debug_boot": "panic-nonce"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        for changes in ({"debug_source": "nvram"}, {"debug_boot": False}, {"trigger": "reboot"}, {"after_debug_boot": "unknown"}):
            self.assertFalse(r.valid_context({**ctx, **changes}, "Darwin", "x86_64", r.KERNEL_UUID))
        data = {"trigger": "reboot-quick", "debug_boot": True, "debug_source": "bootplist", "after_debug_boot": "none"}
        self.assertFalse(r.mode_matches(data, {}, ctx))
        self.assertTrue(r.report_required(ctx))

    def test_followup_proof_keeps_three_boots_distinct(self):
        b1, b2, b3 = (letter * 8 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 12 for letter in ("A", "B", "C"))
        ctx = {"debug_source": "bootplist", "after_debug_boot": "panic-nonce", "trigger": "reboot-quick", "debug_boot": True,
               "run_id": "123", "attempt": "1", "sha": "a" * 40}
        pending = {"nonce": "d" * 64, "baseline_boot_uuid": b1, "cert_fingerprint": "e" * 64}
        scope = {"binding": r.binding(ctx), "nonce": pending["nonce"], "baseline": b1,
                 "source_identity": r.debug_source_identity(), "debug_boot_uuid": b2}
        facts = {"current_boot_uuid": b2, "active_debug_mask": 0x102000, "active_bootargs_status": "observed_debug",
                 "bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "staged"},
                 "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}}
        trigger = {"scope": scope, "helper_sha256": "f" * 64, "helper_pid": 123, "tracer_pid": 456, "ready": True}
        data = {"protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx), **pending,
                "debug_source": "bootplist", "after_debug_boot": "panic-nonce", "trigger": "reboot-quick", "debug_boot": True,
                "current_boot_uuid": b3, "debug_boot_uuid": b2, "debug_boot_facts": facts, "panic_trigger": trigger}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        for invalid in ({"current_boot_uuid": b2}, {"debug_boot_uuid": b1}, {"debug_boot_facts": {**facts, "current_boot_uuid": b3}},
                        {"panic_trigger": {**trigger, "scope": {**scope, "debug_boot_uuid": b3}}},
                        {"panic_trigger": {**trigger, "scope": {**scope, "source_identity": "0" * 64}}}):
            self.assertFalse(r.boot_proof_matches({**data, **invalid}, pending, ctx))

    def followup_fixture(self):
        b1, b2, b3 = (letter * 8 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 12 for letter in ("A", "B", "C"))
        ctx = {"debug_source": "bootplist", "after_debug_boot": "panic-nonce", "trigger": "reboot-quick", "debug_boot": True,
               "run_id": "123", "attempt": "1", "sha": "a" * 40}
        config = {"context": ctx, "baseline": b1, "nonce": "d" * 64, "check_id": 9,
                  "cert_fingerprint": "e" * 64, "debug_source_identity": r.debug_source_identity()}
        scope = {**r.debug_boot_marker(config), "debug_boot_uuid": b2}
        facts = {"current_boot_uuid": b2, "active_debug_mask": 0x102000, "active_bootargs_status": "observed_debug",
                 "bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "staged"},
                 "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}}
        return config, {"scope": scope, "facts": facts}, b3

    def test_followup_source_mismatch_never_prepares_or_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            config['debug_source_identity'] = '0' * 64
            def forbidden(*_args, **_kwargs):
                self.fail('source mismatch reached native preparation or firing')
            with patch.object(r.recovery_panic_control, 'prepare', forbidden), patch.object(r.recovery_panic_control, 'fire', forbidden):
                with self.assertRaises(ValueError):
                    r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertFalse((directory / 'panic-followup-debug.json').exists())

    def test_followup_start_persists_debug_proof_before_ready_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            events = []
            r.private_write(directory / "report-cert.pem", b"public certificate boundary")
            def prepare(*_args, **_kwargs):
                self.assertEqual(r.read_followup_debug(directory, config), saved)
                events.append("prepare")
                (directory / "panic-control").mkdir()
                r.private_write(directory / "panic-control" / "trace.stdout", b"private trace output")
                return {"helper_sha256": "f" * 64}
            def publish(_directory, _config, _token, summary, _title):
                events.append(summary["phase"])
                if summary["phase"] == "panic_intent":
                    self.assertTrue((directory / "panic-followup-trigger.json").exists())
            def fire(_directory, scope, prepared, _save, _sync, ready, _boot, **_kwargs):
                trigger = {"scope": scope, "helper_sha256": prepared["helper_sha256"], "helper_pid": 123, "tracer_pid": 456, "ready": True}
                self.assertTrue(ready(trigger))
                events.append("release")
                return {"phase": "returned"}
            def watch(*_args):
                events.append('watch_ready')
                return object()
            def encrypt(_certificate, metadata, report):
                self.assertEqual(metadata["kind"], "panic_control_failure")
                fragments = r.json.loads(report)
                self.assertEqual(r.base64.b64decode(fragments["trace.stdout"]), b"private trace output")
                return {"cert_fingerprint": config["cert_fingerprint"], "ciphertext": "encrypted-only", "cipher_sha256": "c" * 64}
            def complete(_directory, _config, _current, _token, output, successful, _deadline):
                self.assertFalse(successful)
                self.assertEqual(output.get("text"), "encrypted-only")
                self.assertNotIn("private trace output", r.json.dumps(output))
                self.assertEqual(r.json.loads(output["summary"])["phase"], "panic_returned")
                events.append("returned")
            with patch.object(r.recovery_panic_control, "prepare", prepare), patch.object(r.recovery_panic_control, "fire", fire), \
                    patch.object(r.recovery_nvram_panic, "read_panic_info", lambda: self.fail("boot 2 loaded IOKit before spawning tools")), \
                    patch.object(r, "publish_followup", publish), patch.object(r, "complete_recovery", complete), \
                    patch.object(r, "start_runtime_watch", watch), patch.object(r, "runtime_watch_alive", lambda *_a, **_k: True), \
                    patch.object(r.recovery_reports, "encrypt_bundle", encrypt), \
                    patch.object(r, "boot_uuid", lambda: saved["scope"]["debug_boot_uuid"]):
                r.followup_start(directory, config, saved["scope"]["debug_boot_uuid"], saved["facts"], "token")
            self.assertEqual(events, ["prepare", "panic_prepared", "watch_ready", "panic_intent", "release", "returned"])

    def test_followup_third_boot_bypasses_second_boot_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, b3 = self.followup_fixture()
            r.private_write(directory / "panic-followup-debug.json", r.json.dumps(saved).encode())
            r.private_write(directory / "token", b"synthetic-token")
            calls = []
            def forbidden(*_args, **_kwargs):
                self.fail("third boot reran second-boot restoration or core publication")
            with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: b3), \
                    patch.object(r.recovery_bootplist, "finish", forbidden), patch.object(r, "publish_debug_core", forbidden), \
                    patch.object(r, "followup_finish", lambda *_args: calls.append("capture")):
                r.collect(directory)
            self.assertEqual(calls, ["capture"])
            with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: saved["scope"]["debug_boot_uuid"]), \
                    patch.object(r, "followup_finish", forbidden), patch.object(r, "followup_start", forbidden):
                r.collect(directory)

    def test_followup_capture_is_bound_encrypted_and_immutable(self):
        for matching in (True, False):
            with self.subTest(matching=matching), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, saved, b3 = self.followup_fixture()
                scope = saved["scope"]
                trigger = {"scope": scope, "helper_sha256": "f" * 64, "helper_pid": 123, "tracer_pid": 456, "ready": True}
                prepared = {"helper_sha256": "f" * 64}
                (directory / "panic-control").mkdir()
                for name, value in (("panic-followup-trigger.json", trigger), ("panic-control/release-attempt.json", trigger),
                                    ("panic-control/intent.json", {"scope": scope, "prepared": prepared})):
                    r.private_write(directory / name, r.json.dumps(value).encode())
                r.private_write(directory / "report-cert.pem", b"public certificate boundary")
                nonce = config["nonce"] if matching else "0" * 64
                raw = ("panic(cpu 1 caller 0xff): dtrace: panic action at probe pid123:helper:vz_nonce_" + nonce +
                       ":entry (ecb 0xff)\nKernel UUID: " + r.KERNEL_UUID + "\n").encode()
                cipher = b"encrypted boundary artifact"
                envelope = {"ciphertext": r.base64.b64encode(cipher).decode(), "cipher_sha256": r.hashlib.sha256(cipher).hexdigest(),
                            "cert_fingerprint": config["cert_fingerprint"]}
                outputs = []
                def encrypt(_cert, metadata, report):
                    self.assertEqual(report, raw)
                    self.assertEqual((metadata["baseline_boot_uuid"], metadata["debug_boot_uuid"], metadata["current_boot_uuid"]),
                                     (config["baseline"], scope["debug_boot_uuid"], b3))
                    return envelope
                def complete(_directory, _config, _current, _token, output, successful, _deadline):
                    self.assertEqual(successful, matching)
                    self.assertNotIn("dtrace: panic action", r.json.dumps(output))
                    outputs.append(output)
                with patch.object(r.recovery_panic_control, "validate_prepared", lambda *_, **_kwargs: directory / "helper"), \
                        patch.object(r.recovery_nvram_panic, "read_panic_info", lambda: ("observed", raw)), \
                        patch.object(r.recovery_reports, "encrypt_bundle", encrypt), patch.object(r, "complete_recovery", complete):
                    r.followup_finish(directory, config, b3, saved, "token")
                with patch.object(r.recovery_panic_control, "validate_prepared", lambda *_, **_kwargs: directory / "helper"), \
                        patch.object(r.recovery_nvram_panic, "read_panic_info", lambda: self.fail("reread first observation")), \
                        patch.object(r.recovery_reports, "encrypt_bundle", encrypt), patch.object(r, "complete_recovery", complete):
                    r.followup_finish(directory, config, b3, saved, "token")
                self.assertEqual(outputs[0], outputs[1])
                summary = r.json.loads(outputs[0]["summary"])
                self.assertEqual(summary["debug_boot_facts"]["current_boot_uuid"], scope["debug_boot_uuid"])
                self.assertEqual(summary["current_boot_uuid"], b3)
                self.assertEqual(summary["capture_state"], "fresh_fragment" if matching else "encrypted_unvalidated")

    def owner_fixture(self, directory):
        config = {"debug_source": "nvram", "context": {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True, "trigger": "reboot"},
                  "debug_boot": True, "baseline": "old", "nonce": "b" * 64, "debug_source_identity": r.debug_source_identity()}
        original = {"boot-args": b"preempt=10"}
        class Platform:
            fail_write = False
            def __init__(self):
                self.value = original.copy()
                self.active_value = b"preempt=10"
                self.events = []
            def read(self):
                return self.value.copy()
            def active(self):
                return self.active_value
            def write(self, path, owned_canary, expected_previous):
                self.events.append("write")
                self.value = r.recovery_bootargs.parse_nvram(path.read_bytes())
                if self.fail_write:
                    self.fail_write = False
                    raise OSError("write response lost")
            def inventory(self):
                self.events.append("inventory")
                return {"nic_inventory_status": "unsupported"}
        r.debug_event(directory, config, "request", "old")
        return config, Platform(), original

    def test_owner_preintent_failure_restores_without_reboot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            platform.fail_write = True
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("preintent reboot")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            self.assertFalse((directory / "debug-reboot-intent.json").exists())
            self.assertTrue((directory / "debug-reboot-aborted.json").exists())

    def test_owner_sync_request_failure_prevents_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, _platform, original = self.owner_fixture(directory)
            state, syncs = original.copy(), []
            def capture(argv, *_args):
                if argv == ["/usr/sbin/nvram", "-x", "-p"]:
                    return r.recovery_bootargs.plistlib.dumps(state)
                if argv[0] == "/usr/sbin/sysctl":
                    return b"preempt=10\n"
                if argv[1:3] == ["-x", "-f"]:
                    state.update(r.recovery_bootargs.parse_nvram(Path(argv[3]).read_bytes()))
                    return b""
                if argv[1] == "-d":
                    state.pop(argv[2], None)
                    return b""
                self.assertEqual(argv, ["/usr/sbin/nvram", "-s"])
                syncs.append("sync")
                if len(syncs) == 1:
                    raise OSError("sync request failed")
                return b""
            with patch.object(r.recovery_bootargs, "capture", capture), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("reboot after failed sync")):
                r.debug_owner(directory, config, "old")
            self.assertFalse((directory / "debug-reboot-intent.json").exists())
            self.assertEqual(state, original)
            self.assertEqual(syncs, ["sync", "sync", "sync"])

    def test_owner_postintent_timeout_or_signal_never_kills_restores_or_retries(self):
        for failure in (subprocess.TimeoutExpired("reboot", 15), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                calls = []
                class Child:
                    pid = 1234
                    def wait(self, timeout):
                        raise failure
                    def kill(self):
                        raise AssertionError("postintent kill")
                def popen(*_args, **_kwargs):
                    calls.append("reboot")
                    return Child()
                with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                        patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), patch.object(r.subprocess, "Popen", popen):
                    r.debug_owner(directory, config, "old")
                    r.debug_owner(directory, config, "old")
                self.assertNotEqual(platform.value, original)
                self.assertEqual(calls, ["reboot"])
                self.assertTrue((directory / "debug-reboot-intent.json").exists())
                self.assertFalse((directory / "debug-boot-restored.json").exists())

    def test_owner_orphan_stage_restores_without_reboot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            r.recovery_bootargs.stage(directory, r.debug_boot_marker(config), platform, r.private_write, r.sync_directory)
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("orphan stage reboot")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            record = r.read_debug_event(directory, config, "aborted")
            self.assertEqual(record["reason"], "orphan_stage")
            self.assertEqual(record["nvram_before_rollback"], "staged")

    def test_owner_returned_request_is_immutable_and_never_reissued(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, _original = self.owner_fixture(directory)
            request = directory / "debug-reboot-request.json"
            first = request.read_bytes()
            r.debug_event(directory, config, "request", "old", reason="interrupted")
            self.assertEqual(request.read_bytes(), first)
            calls = []
            def reboot():
                calls.append("reboot")
                return {"returncode": 0, "reboot_pid": 1234}
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), patch.object(r, "debug_reboot_child", reboot):
                r.debug_owner(directory, config, "old")
                r.debug_owner(directory, config, "old")
            self.assertEqual(calls, ["reboot"])
            self.assertEqual(r.read_debug_event(directory, config, "returned")["returncode"], 0)
            self.assertFalse((directory / "debug-boot-restored.json").exists())

    def test_native_sync_fact_requires_exact_success(self):
        good = b'{"event":"sync","status":"returned","ioreturn":0}\n'
        states = {'boot_args': 'staged', 'canary': 'staged'}
        fact = r.native_sync_fact(good, 0, states, states, 'a' * 64, 'b' * 64)
        self.assertEqual(fact['ioreturn'], 0)
        self.assertEqual(fact['after_key_states'], states)
        for raw, code, keys in ((good, 70, states), (good + good, 0, states),
                                (good.replace(b':0', b':true'), 0, states),
                                (good, 0, {'boot_args': 'original', 'canary': 'staged'})):
            with self.assertRaises(ValueError): r.native_sync_fact(raw, code, states, keys, 'a' * 64, 'b' * 64)

    def test_native_spawn_interruption_is_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            helper = directory / 'nvram-backend'
            helper.write_bytes(b'synthetic helper')
            config = {'baseline': 'old', 'nonce': 'b' * 64,
                      'nvram_helper_sha256': r.hashlib.sha256(helper.read_bytes()).hexdigest(),
                      'context': {"debug_source": "nvram", 'actions': 'true', 'event': 'workflow_dispatch', 'repo': 'Code-Hex/vz-ci-test',
                                  'ref': 'refs/heads/main', 'runner_environment': 'github-hosted',
                                  'run_id': '123', 'attempt': '1', 'sha': 'a' * 40, 'trigger': 'reboot-quick'}}
            with patch.object(r, 'boot_uuid', lambda: 'old'), patch.object(r.subprocess, 'Popen', side_effect=KeyboardInterrupt()):
                try:
                    r.invoke_native_helper(directory, config)
                except BaseException as error:
                    self.assertIsInstance(error, r.NativeSyncUncertain)
                else:
                    self.fail('interrupted spawn reported success')

    def test_native_failure_fact_preserves_only_bounded_status(self):
        raw = b'{"event":"sync","status":"returned","ioreturn":3758097084,"private":"never"}\n'
        self.assertEqual(r.native_failure_fact(raw, 70), {'status': 'returned', 'exit': 70, 'ioreturn': 3758097084})
        self.assertEqual(r.native_failure_fact(raw.replace(b'3758097084', b'true'), 70), {'status': 'invalid'})

    def test_debug_quick_owner_ack_before_intent_and_no_reissue(self):
        for acknowledged, intent_acknowledged in ((True, True), (True, False), (False, True)):
            with self.subTest(acknowledged=acknowledged, intent_acknowledged=intent_acknowledged), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                config["context"]["trigger"] = "reboot-quick"
                config.update({"nvram_helper_sha256": "a" * 64, "nvram_source_sha256": "b" * 64})
                native_fact = r.native_sync_fact(b'{"event":"sync","status":"returned","ioreturn":0}', 0,
                    {"boot_args": "staged", "canary": "staged"}, {"boot_args": "staged", "canary": "staged"}, "a" * 64, "b" * 64)
                events = []
                def prepare(*_args):
                    self.assertNotEqual(platform.value, original)
                    self.assertTrue((directory / "debug-reboot-staged.json").exists())
                    self.assertFalse((directory / "debug-reboot-intent.json").exists())
                    events.append("prepare_ack")
                    if not acknowledged:
                        raise ValueError("checkpoint not acknowledged")
                    return {"phase": "quick_prepared"}
                def intent_ack(*_args):
                    self.assertTrue((directory / "debug-reboot-intent.json").exists())
                    self.assertFalse((directory / "debug-boot-restored.json").exists())
                    events.append("intent_ack")
                    if not intent_acknowledged:
                        raise ValueError("intent checkpoint not acknowledged")
                    return _args[2]
                def execute(*_args, **_kwargs):
                    self.assertTrue((directory / "debug-reboot-intent.json").exists())
                    events.append("execute")
                    return {"reason": "exec_error"}
                with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                        patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                        patch.object(r, "native_force_sync", lambda *_args: native_fact), \
                        patch.object(r, "quick_prepare", prepare), patch.object(r, "quick_reboot_child", execute), \
                        patch.object(r, "quick_intent_ack", intent_ack), \
                        patch.object(r, "debug_reboot_child", lambda: self.fail("normal reboot fallback")):
                    r.debug_owner(directory, config, "old")
                    r.debug_owner(directory, config, "old")
                expected = ["prepare_ack"] + (["intent_ack"] if acknowledged else [])
                if acknowledged and intent_acknowledged:
                    expected.append("execute")
                self.assertEqual(events, expected)
                self.assertEqual(platform.value == original, not acknowledged)
                self.assertEqual((directory / "debug-boot-restored.json").exists(), not acknowledged)
                if acknowledged and not intent_acknowledged:
                    self.assertEqual(r.read_debug_event(directory, config, "uncertain")["reason"], "intent_ack_failure")

    def test_unsettled_native_marker_blocks_retry_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config["context"]["trigger"] = "reboot-quick"
            r.debug_event(directory, config, "native_inflight", "old")
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: self.fail("unsettled native owner retried")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            self.assertFalse((directory / "debug-reboot-aborted.json").exists())
            self.assertFalse((directory / "debug-reboot-intent.json").exists())
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config["context"]["trigger"] = "reboot-quick"
            r.debug_event(directory, config, "rollback_inflight", "old")
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: self.fail("unsettled cleanup retried")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)

    def test_uncertain_native_and_invalid_terminal_never_mutate_again(self):
        for variant in ('uncertain', 'partial_synced', 'partial_failed', 'uncertain_failed', 'inconsistent_failed'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                config["context"]["trigger"] = "reboot-quick"
                calls = []
                if variant == 'uncertain':
                    def native(*_args):
                        calls.append('native')
                        raise r.NativeSyncUncertain()
                    with patch.object(r.recovery_bootargs, 'MacPlatform', lambda: platform), \
                            patch.object(r.recovery_bootargs, 'csr_allowed', lambda: True), \
                            patch.object(r, 'native_force_sync', native), \
                            patch.object(r.recovery_bootargs, 'rollback', lambda *_a, **_k: self.fail('uncertain rollback')), \
                            patch.object(r, 'rollback_native_sync', lambda *_: self.fail('uncertain cleanup')), \
                            patch.object(r, 'quick_reboot_child', lambda *_a, **_k: self.fail('uncertain reboot')):
                        r.debug_owner(directory, config, 'old')
                        r.debug_owner(directory, config, 'old')
                    self.assertEqual(calls, ['native'])
                    self.assertNotEqual(platform.value, original)
                else:
                    r.debug_event(directory, config, 'native_inflight', 'old')
                    event = 'native_synced' if variant == 'partial_synced' else 'native_failed'
                    path = directory / ('debug-reboot-' + event + '.json')
                    if variant == 'uncertain_failed':
                        r.debug_event(directory, config, event, 'old', sync_result={'status': 'failed_or_uncertain'})
                    elif variant == 'inconsistent_failed':
                        r.debug_event(directory, config, event, 'old', sync_result={'status': 'returned', 'exit': 0, 'ioreturn': 123})
                    else:
                        path.write_text('{')
                    with patch.object(r.recovery_bootargs, 'MacPlatform', lambda: self.fail('invalid record retried')):
                        r.debug_owner(directory, config, 'old')
                self.assertFalse((directory / 'debug-reboot-aborted.json').exists())
                self.assertFalse((directory / 'debug-reboot-intent.json').exists())

    def test_uncertain_cleanup_retains_marker_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config['context']['trigger'] = 'reboot-quick'
            calls = []
            def native(*_args):
                calls.append('native')
                raise r.NativeSyncFailure({'status': 'returned', 'exit': 70, 'ioreturn': 123})
            def cleanup(*_args):
                calls.append('cleanup')
                raise r.NativeSyncUncertain()
            with patch.object(r.recovery_bootargs, 'MacPlatform', lambda: platform), \
                    patch.object(r.recovery_bootargs, 'csr_allowed', lambda: True), \
                    patch.object(r, 'native_force_sync', native), patch.object(r, 'rollback_native_sync', cleanup), \
                    patch.object(r, 'quick_reboot_child', lambda *_a, **_k: self.fail('unexpected reboot')):
                r.debug_owner(directory, config, 'old')
                r.debug_owner(directory, config, 'old')
            self.assertEqual(calls, ['native', 'cleanup'])
            self.assertEqual(platform.value, original)
            self.assertTrue((directory / 'debug-reboot-rollback_inflight.json').exists())
            self.assertFalse((directory / 'debug-reboot-rollback_cleanup.json').exists())
            self.assertFalse((directory / 'debug-reboot-aborted.json').exists())

    def test_native_failure_rolls_back_and_never_reboots(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config["context"]["trigger"] = "reboot-quick"
            calls = []
            def native(*_args):
                calls.append("native")
                raise r.NativeSyncFailure({"status": "returned", "exit": 70, "ioreturn": 123})
            def cleanup(*_args):
                self.assertEqual(platform.value, original)
                calls.append("cleanup")
                return {"status": "returned", "exit": 0, "ioreturn": 0, "sameboot_readback_original": True}
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                    patch.object(r, "native_force_sync", native), patch.object(r, "rollback_native_sync", cleanup), \
                    patch.object(r, "quick_prepare", lambda *_: self.fail("prepare after native failure")), \
                    patch.object(r, "quick_reboot_child", lambda *_a, **_k: self.fail("reboot after native failure")):
                r.debug_owner(directory, config, "old")
                r.debug_owner(directory, config, "old")
            self.assertEqual(calls, ["native", "cleanup"])
            self.assertEqual(platform.value, original)
            self.assertEqual(r.read_debug_event(directory, config, "native_failed")["sync_result"]["ioreturn"], 123)
            self.assertTrue(r.read_debug_event(directory, config, "rollback_cleanup")["sync_result"]["sameboot_readback_original"])
            self.assertFalse((directory / "debug-reboot-intent.json").exists())

    def test_quick_intent_canonical_ack_preserves_prepared_and_filters_owner_fields(self):
        for source, acknowledged in (("nvram", True), ("nvram", False), ("bootplist", True), ("bootplist", False)):
            with self.subTest(acknowledged=acknowledged), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update(trigger="reboot-quick", debug_source=source)
                config["check_id"] = 9
                config.update({"nvram_helper_sha256": "a" * 64, "nvram_source_sha256": "b" * 64})
                ctx = config["context"]
                config["cert_fingerprint"] = "e" * 64 if source == "bootplist" else ""
                prepared = {"debug_source": source, "protocol": "vz-recovery-v1", "phase": "quick_prepared", "binding": r.binding(ctx),
                            "nonce": config["nonce"], "baseline_boot_uuid": config["baseline"], "trigger": "reboot-quick",
                            "debug_boot": True, "cert_fingerprint": config["cert_fingerprint"], "quick_flags": 1024, "helper_sha256": "c" * 64,
                            "permission_verified": False}
                r.private_write(directory / "token", b"synthetic-token")
                for event in ("staged", "intent"):
                    r.debug_event(directory, config, event, "old")
                native_fact = r.native_sync_fact(b'{"event":"sync","status":"returned","ioreturn":0}', 0,
                    {"boot_args": "staged", "canary": "staged"}, {"boot_args": "staged", "canary": "staged"}, "a" * 64, "b" * 64)
                evidence = "native_synced" if source == "nvram" else "bootplist_staged"
                if source == "nvram":
                    r.debug_event(directory, config, evidence, "old", native_sync=native_fact)
                else:
                    r.debug_event(directory, config, evidence, "old", bootplist_stage={"data": "staged", "preboot": "staged", "metadata_preserved": True})
                path = directory / "debug-reboot-staged.json"
                raw = r.json.loads(path.read_text())
                path.write_text(r.json.dumps({**raw, "raw": "private-not-published"}))
                sent, operations = {}, []
                def api(method, _url, token, payload=None):
                    self.assertEqual(token, "synthetic-token")
                    operations.append(method)
                    if method == "PATCH":
                        sent.update(payload)
                        return {}
                    return {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                            "app": {"id": 15368 if acknowledged else 0, "slug": "github-actions"},
                            "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9", "status": "in_progress",
                            "conclusion": None, "output": sent["output"]}
                with patch.object(r, "api", api), patch.object(r, "boot_uuid", lambda: "old"):
                    if acknowledged:
                        result = r.quick_intent_ack(directory, config, prepared)
                        self.assertEqual(result["phase"], "quick_intent")
                        with self.assertRaises(ValueError):
                            r.quick_intent_ack(directory, config, {**prepared, "cert_fingerprint": "0" * 64})
                    else:
                        with self.assertRaises(ValueError):
                            r.quick_intent_ack(directory, config, prepared)
                self.assertEqual(operations, ["PATCH", "GET"])
                summary = r.json.loads(sent["output"]["summary"])
                self.assertEqual({key: summary[key] for key in prepared if key != "phase"},
                                 {key: value for key, value in prepared.items() if key != "phase"})
                self.assertEqual([event["event"] for event in summary["owner_events"]], ["staged", evidence, "intent"])
                self.assertNotIn("private-not-published", sent["output"]["summary"])

    def test_quick_timeout_retains_same_child_until_exit_without_kill(self):
        for interruption in (subprocess.TimeoutExpired("helper", 30), KeyboardInterrupt()):
            with self.subTest(interruption=type(interruption).__name__), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update({"debug_source": "nvram", "actions": "true", "event": "workflow_dispatch", "repo": "Code-Hex/vz-ci-test",
                                          "ref": "refs/heads/main", "runner_environment": "github-hosted", "trigger": "reboot-quick"})
                helper = directory / "reboot-quick"
                helper.write_bytes(b"synthetic helper")
                config["helper_sha256"] = r.hashlib.sha256(helper.read_bytes()).hexdigest()
                waits, notices, starts = [], [], []
                class Child:
                    returncode, pid = 70, 1234
                    def communicate(self, timeout):
                        waits.append(timeout)
                        if len(waits) == 1:
                            raise interruption
                        return ('{"event":"quick_reboot_unexpected_return","result":-1,"errno":1}', '')
                    def kill(self):
                        raise AssertionError("helper killed")
                def popen(command, **kwargs):
                    starts.append(command)
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    return Child()
                with patch.object(r.subprocess, "Popen", popen):
                    result = r.quick_reboot_child(directory, config, notices.append)
                self.assertEqual(waits, [30, None])
                self.assertEqual(notices, ["timeout" if isinstance(interruption, subprocess.TimeoutExpired) else "interrupted"])
                self.assertEqual(starts, [[str(helper), "execute"]])
                self.assertEqual(result["quick_return"]["errno"], 1)

    def test_newboot_core_ack_precedes_inventory_and_failed_ack_skips_it(self):
        for acknowledged, restored in ((True, True), (False, True), (True, False)):
            with self.subTest(acknowledged=acknowledged, restored=restored), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                config["check_id"] = 9
                r.recovery_bootargs.stage(directory, r.debug_boot_marker(config), platform, r.private_write, r.sync_directory)
                platform.active_value = b"preempt=10 debug=0x2000"
                platform.events.clear()
                r.private_write(directory / "token", b"test-token")
                r.private_write(directory / "ready.json", r.json.dumps({"baseline": "old", "nonce": config["nonce"], "preboot_patch": True}).encode())
                output = {}
                final_conclusions = []
                original_finish = r.recovery_bootargs.finish
                def finish(*args, **kwargs):
                    if not restored:
                        raise OSError("restoration unavailable")
                    return original_finish(*args, **kwargs)
                def api(method, _url, _token, payload=None, **_kwargs):
                    if method == "PATCH" and payload.get("status") == "in_progress":
                        platform.events.append("core_patch")
                        output.update(payload["output"])
                        return {}
                    if method == "GET":
                        platform.events.append("core_ack")
                        ctx = config["context"]
                        return {"id": 9, "name": "Runner recovery " + ctx["run_id"], "head_sha": ctx["sha"],
                                "external_id": r.binding(ctx), "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                                "app": {"id": 15368 if acknowledged else 0, "slug": "github-actions"},
                                "status": "in_progress", "conclusion": None, "output": output.copy()}
                    platform.events.append("final_patch")
                    final_conclusions.append(payload["conclusion"])
                    error = r.urllib.error.HTTPError("https://api.github.com", 401, "test refusal", {}, None)
                    self.addCleanup(error.close)
                    raise error
                with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: "new"), \
                        patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), patch.object(r, "api", api), \
                        patch.object(r.recovery_bootargs, "finish", finish), \
                        patch.object(r, "debug_owner", lambda *_: self.fail("newboot invoked oldboot owner")):
                    r.collect(directory)
                if restored:
                    self.assertEqual(platform.value, original)
                    self.assertLess(platform.events.index("write"), platform.events.index("core_patch"))
                self.assertTrue((directory / "debug-boot-core.json").exists())
                self.assertEqual(r.json.loads((directory / "debug-boot-core.json").read_text())["facts"]["nvram_restored"], restored)
                if not restored:
                    self.assertEqual(r.json.loads((directory / "debug-boot-core.json").read_text())["facts"]["nvram_key_states"],
                                     {"boot_args": "unavailable", "canary": "unavailable"})
                if acknowledged and restored:
                    self.assertLess(platform.events.index("core_ack"), platform.events.index("inventory"))
                    self.assertLess(platform.events.index("inventory"), platform.events.index("final_patch"))
                    self.assertEqual(final_conclusions, ["success"])
                elif acknowledged:
                    self.assertNotIn("inventory", platform.events)
                    self.assertEqual(final_conclusions, ["failure"])
                else:
                    self.assertNotIn("inventory", platform.events)
                    self.assertNotIn("final_patch", platform.events)

    def test_default_reboot_path_still_uses_existing_command(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return "ready"
        def run(command, **kwargs):
            calls.append((command, kwargs))
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot", "debug_boot": False}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", lambda: calls.append("sync")), patch.object(r.subprocess, "run", run), \
                contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, ["verify-root", "sync", (["/usr/bin/sudo", "-n", "/sbin/reboot"], {"check": True, "timeout": 15})])

    def test_debug_controller_stop_does_not_overwrite_new_core_after_stale_get(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True}
        armed = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                 "app": {"id": 15368, "slug": "github-actions"}, "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                 "status": "in_progress", "output": {"summary": '{"phase":"armed"}'}}
        core = {"title": "Boot core recovered", "summary": '{"phase":"boot_core","immutable_fact":true}'}
        server, patches = {"output": armed["output"]}, []
        def api(method, _url, _token, payload=None, **_kwargs):
            if method == "GET":
                server["output"] = core.copy()
                return armed
            self.assertEqual(method, "PATCH")
            patches.append(payload)
            server.update(payload)
            return {}
        def stop(_seconds):
            raise RuntimeError("controller interrupted")
        with patch.object(r, "list_check", lambda *_: armed), patch.object(r, "api", api), \
                patch.object(r.time, "sleep", stop), patch.object(r.signal, "signal", lambda *_: None):
            with self.assertRaises(RuntimeError):
                r.controller(ctx, "test-token")
        self.assertEqual(patches, [{"status": "completed", "conclusion": "failure"}])
        self.assertEqual(server["output"], core)

    def test_rsa_oaep_sha256_roundtrip_and_key_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "key.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(private)], check=True, stderr=subprocess.DEVNULL)
            public = subprocess.check_output(["openssl", "pkey", "-in", str(private), "-pubout"])
            ciphertext = r.encrypt_token(public, "test-job-token")
            self.assertNotIn(b"test-job-token", ciphertext)
            self.assertEqual(r.decrypt_token(private, ciphertext), "test-job-token")
            small = Path(tmp) / "small.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(small)], check=True, stderr=subprocess.DEVNULL)
            invalid = subprocess.check_output(["openssl", "pkey", "-in", str(small), "-pubout"])
            with self.assertRaises(ValueError):
                r.encrypt_token(invalid, "test-job-token")

    def test_sealed_retry_and_boot_proof_match_nonce_and_baseline(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "2", "sha": "a" * 40}
        pending = {"nonce": "b" * 64, "baseline_boot_uuid": "first", "ciphertext": "cipher"}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "sealed_token", **pending}
        self.assertTrue(r.sealed_matches(data, pending, ctx))
        self.assertFalse(r.sealed_matches(dict(data, ciphertext="other"), pending, ctx))
        proof = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "boot_observed",
                 "nonce": pending["nonce"], "baseline_boot_uuid": "first", "current_boot_uuid": "second"}
        armed = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "armed", "nonce": pending["nonce"], "baseline_boot_uuid": "first"}
        self.assertTrue(r.armed_matches(armed, pending, ctx))
        self.assertFalse(r.armed_matches(dict(armed, baseline_boot_uuid="other"), pending, ctx))
        self.assertTrue(r.boot_proof_matches(proof, pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, nonce="wrong"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, baseline_boot_uuid="other"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, current_boot_uuid="first"), pending, ctx))

    def test_panic_proof_requires_matching_ciphertext(self):
        import base64
        import hashlib
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "trigger": "panic-control"}
        pending = {"nonce": "b" * 64, "baseline_boot_uuid": "old", "cert_fingerprint": "c" * 64}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "boot_observed", "nonce": pending["nonce"],
                "baseline_boot_uuid": "old", "current_boot_uuid": "new", "trigger": "panic-control",
                "cert_fingerprint": pending["cert_fingerprint"], "capture_state": "captured", "cipher_sha256": hashlib.sha256(b"cipher").hexdigest()}
        encoded = base64.b64encode(b"cipher").decode()
        self.assertTrue(r.panic_envelope_matches(data, encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(data, base64.b64encode(b"other").decode(), pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, capture_state="missing"), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, cert_fingerprint="d" * 64), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, trigger="reboot"), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, baseline_boot_uuid="wrong"), encoded, pending, ctx))
        force_ctx = dict(ctx, trigger="panic-force-reset")
        self.assertTrue(r.panic_envelope_matches(dict(data, trigger="panic-force-reset"), encoded, pending, force_ctx))
        self.assertFalse(r.panic_envelope_matches(data, encoded, pending, force_ctx))

    def test_old_check_cleanup_validates_canonical_binding(self):
        old_sha = "a" * 40
        old = {"id": 126478800449, "name": "Runner recovery 41801686112", "head_sha": old_sha,
               "external_id": "41801686112/1/" + old_sha, "app": {"slug": "github-actions", "id": 15368},
               "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/126478800449", "status": "in_progress"}
        current = {"run_id": "999", "attempt": "1", "sha": "b" * 40}
        self.assertTrue(r.cleanup_eligible(old, "126478800449", current))
        self.assertFalse(r.cleanup_eligible(old, "0", current))
        self.assertFalse(r.cleanup_eligible(old, "../126478800449", current))
        self.assertFalse(r.cleanup_eligible(old, "126478800449", dict(current, run_id="41801686112")))
        self.assertFalse(r.cleanup_eligible(dict(old, head_sha="b" * 40), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, status="completed"), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, status="unknown"), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, app={"id": 9, "slug": "github-actions"}), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, details_url="https://evil.example"), "126478800449", current))

    def test_binding_exact_and_no_duplicate(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "2", "sha": "a" * 40}
        check = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx),
                 "head_sha": ctx["sha"], "app": {"slug": "github-actions", "id": 15368},
                 "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9", "status": "in_progress"}
        self.assertEqual(r.select_check([check], ctx)["id"], 9)
        self.assertIsNone(r.select_check([dict(check, external_id="wrong")], ctx))
        self.assertIsNone(r.select_check([dict(check, app={"id": 7, "slug": "github-actions"})], ctx))
        self.assertIsNone(r.select_check([dict(check, details_url="https://example.com")], ctx))
        self.assertIsNone(r.select_check([dict(check, details_url="https://github.com/Code-Hex/vz-ci-test/runs/10")], ctx))
        self.assertIsNone(r.select_check([dict(check, id="9")], ctx))
        with self.assertRaises(ValueError):
            r.select_check([check, check], ctx)


if __name__ == "__main__":
    unittest.main()
