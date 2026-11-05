import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import recovery_panic_control as control


class PanicControl(unittest.TestCase):
    def test_closed_control_kind_is_rejected_before_file_io(self):
        for function, args in ((control.build, ('/missing', 'a'*64, None, None)),
                               (control.validate_built, ('/missing', 'a'*64)),
                               (control.prepare, ('/missing', 'a'*64, None, None)),
                               (control.validate_prepared, ('/missing', 'a'*64, {})),
                               (control.fire, ('/missing', {}, {}, None, None, None, None))):
            with self.assertRaisesRegex(ValueError, 'control_kind_invalid'): function(*args, control_kind='unknown')

    def test_usdt_native_build_exact_receipts_and_cross_kind_tamper_rejection(self):
        import json
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def save(path, data):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream: stream.write(data)
            sync = lambda _: None
            built = control.build(root, 'a'*64, save, sync, control_kind='usdt-v1')
            self.assertEqual(set(built), {'control_sha256', 'preflight_sha256', 'getter_sha256', 'usdt_core_sha256',
                'helper_source_sha256', 'helper_sha256', 'nonce_sha256', 'build_status', 'sign_status', 'signature_status',
                'control_kind', 'provider_source_sha256', 'provider_header_sha256'})
            self.assertEqual(control.validate_built(root, 'a'*64, control_kind='usdt-v1'), built)
            with self.assertRaises(ValueError): control.validate_built(root, 'a'*64)
            private = root/'panic-control'
            phases = []
            def observe(binary, nonce, directory, facts, *, env, on_timeout, control_kind, deadline):
                phases.append(('observe', binary, control_kind, deadline))
            def compile_only(binary, nonce, directory, *, env, on_timeout, control_kind, deadline):
                phases.append(('compile', binary, control_kind, deadline)); return True
            prepared = control.prepare(root, 'a'*64, save, sync, control_kind='usdt-v1',
                                       observe=observe, compile_only=compile_only, deadline=time.monotonic()+55)
            self.assertEqual(set(prepared), {'control_sha256', 'preflight_sha256', 'getter_sha256', 'usdt_core_sha256',
                'helper_source_sha256', 'helper_sha256', 'nonce_sha256', 'observe_status', 'compile_status', 'control_kind',
                'provider_source_sha256', 'provider_header_sha256'})
            self.assertEqual([phase[0] for phase in phases], ['observe', 'compile'])
            self.assertEqual(phases[0][1:], phases[1][1:])
            self.assertEqual(prepared['helper_sha256'], built['helper_sha256'])
            self.assertEqual(control.validate_prepared(root, 'a'*64, prepared, control_kind='usdt-v1'), private/'helper')
            with self.assertRaises(ValueError): control.validate_prepared(root, 'a'*64, prepared)
            for key in ('control_kind', 'usdt_core_sha256', 'provider_source_sha256', 'provider_header_sha256'):
                changed = {**prepared, key: 'pid-v1' if key == 'control_kind' else '0'*64}
                with self.assertRaises(ValueError): control.validate_prepared(root, 'a'*64, changed, control_kind='usdt-v1')
            for name in ('provider.d', 'provider.h', 'helper.c', 'helper'):
                path=private/name; original=path.read_bytes()
                try:
                    path.write_bytes(original+b'changed')
                    with self.assertRaises(ValueError): control.validate_prepared(root, 'a'*64, prepared, control_kind='usdt-v1')
                finally: path.write_bytes(original)
            (private/'prepared.json').unlink()
            def failed_compile(*args, **kwargs): return False
            with self.assertRaisesRegex(ValueError, 'panic_compile_failed'):
                control.prepare(root, 'a'*64, save, sync, control_kind='usdt-v1', observe=observe, compile_only=failed_compile)
            self.assertFalse((private/'prepared.json').exists())

    def test_startup_window_reserves_profiler_and_owned_child_reaping(self):
        now=time.monotonic()
        operation, outer=control.startup_window(now+30,40)
        self.assertLessEqual(operation, now+13)
        self.assertEqual(outer, now+30)
        with self.assertRaises(TimeoutError): control.startup_window(now+16,40)
        for value in (True, float('nan'), float('inf'), 'deadline'):
            with self.assertRaises(ValueError): control.startup_window(value,40)

    def test_usdt_fire_native_helpers_ack_deadline_and_once_ownership_without_dtrace(self):
        import json, shutil
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'base'; base.mkdir()
            def save(path,data):
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream: stream.write(data)
            sync=lambda _:None
            built=control.build(base,'a'*64,save,sync,control_kind='usdt-v1')
            private=base/'panic-control'; preflight=control.load_preflight()
            preflight.command(['/usr/bin/xcrun','clang','-arch',os.uname().machine,'-O0',str(private/'helper.c'),'-o',str(private/'helper')],private,'native-build')
            preflight.command(['/usr/bin/codesign','-s','-','-f',str(private/'helper')],private,'native-sign')
            (private/'helper').chmod(0o700)
            built['helper_sha256']=control.digest((private/'helper').read_bytes())
            (private/'built.json').write_text(json.dumps(built))
            prepared=control.prepare(base,'a'*64,save,sync,control_kind='usdt-v1',
                observe=lambda *a,**k:True,compile_only=lambda *a,**k:True)
            scope={'binding':'123/1/'+'a'*40,'nonce':'a'*64,'source_identity':'b'*64,
                   'baseline':'11111111-1111-1111-1111-111111111111',
                   'debug_boot_uuid':'22222222-2222-2222-2222-222222222222'}
            for case in ('accepted','rejected','expired'):
                with self.subTest(case=case):
                    root=Path(tmp)/case; root.mkdir(); shutil.copytree(private,root/'panic-control')
                    children=[]; events=[]
                    class OwnedTracer(subprocess.Popen):
                        def kill(self):
                            if case=='accepted': raise AssertionError('after-G kill')
                            return super().kill()
                    def run_command(argv,directory,label,timeout,**kwargs):
                        self.assertEqual(label,'fire-listing')
                        spec=control.usdt.ProbeSpec('a'*64)
                        helperpid=int(argv[-1].split(':')[0][len(spec.provider):])
                        probe=spec.bind(helperpid)
                        program='print('+repr('ID PROVIDER MODULE FUNCTION NAME\n1 '+' '.join(probe.fields)+'\n')+',end="")'
                        return preflight.command([sys.executable,'-c',program],directory,label,timeout,**kwargs)
                    def start_tracer(argv,**kwargs):
                        self.assertNotIn('-p',argv); self.assertIn('{ panic(); }',argv[-1])
                        child=OwnedTracer([sys.executable,'-c','import time; print("READY",flush=True); time.sleep('+('2' if case=='expired' else '.2')+')'],**kwargs)
                        children.append(child); return child
                    def on_ready(trigger):
                        self.assertEqual(set(trigger),{'scope','helper_sha256','helper_pid','tracer_pid','ready'})
                        events.append(trigger)
                        if case=='expired': time.sleep(.55)
                        return case!='rejected'
                    result=control.fire(root,scope,prepared,save,sync,on_ready,lambda:scope['debug_boot_uuid'],
                        control_kind='usdt-v1',deadline=time.monotonic()+(17.5 if case=='expired' else 25),
                        run_command=run_command,start_tracer=start_tracer)
                    self.assertEqual(len(events),1)
                    self.assertEqual(result['release_status'],'released' if case=='accepted' else 'not_released')
                    self.assertEqual((root/'panic-control'/'release-attempt.json').exists(),case=='accepted')
                    self.assertEqual(len(children),1); self.assertIsNotNone(children[0].poll())
                    if case=='accepted': self.assertEqual((result['helper_exit'],result['tracer_exit']),(0,0))

    def test_usdt_input_closes_only_after_both_owned_exit_results(self):
        helper=subprocess.Popen([sys.executable,'-c','import sys; sys.stdin.buffer.read(1)'],stdin=subprocess.PIPE)
        try:
            control.close_exited_usdt_input(helper,{'helper_exit':None,'tracer_exit':0})
            self.assertFalse(helper.stdin.closed)
            helper.stdin.write(b'X'); helper.stdin.flush(); self.assertEqual(helper.wait(timeout=2),0)
            control.close_exited_usdt_input(helper,{'helper_exit':0,'tracer_exit':0})
            self.assertTrue(helper.stdin.closed)
        finally:
            if not helper.stdin.closed: helper.stdin.close()
            if helper.poll() is None: helper.kill(); helper.wait(timeout=2)

    def test_prepare_failure_records_timeout_stage_without_raw_data(self):
        import json
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def save(path, data):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
            facts = {'list_status': 'matched', 'ready_count': 1, 'hit_count': 0,
                     'provider_exact': None, 'trace_stderr': 'other', 'private': 'secret-token'}
            with self.assertRaises(subprocess.TimeoutExpired):
                with control.PrepareProgress(root, save, lambda _: None, facts) as progress:
                    progress.stage = 'observe'
                    subprocess.run([sys.executable, '-c', 'import time; time.sleep(1)'], timeout=0.03)
            value = json.loads((root / 'prepare-failure.json').read_text())
            self.assertEqual((value['stage'], value['kind']), ('observe', 'timeout'))
            self.assertEqual(value['observe']['list_status'], 'matched')
            self.assertEqual(value['observe']['ready_count'], 1)
            self.assertNotIn('secret-token', str(value))
            self.assertFalse((root / 'prepared.json').exists())

    def test_failure_record_error_does_not_replace_original_error(self):
        with tempfile.TemporaryDirectory() as temp:
            def fail_save(path, data): raise OSError('private storage unavailable')
            original = TimeoutError('private detail')
            with self.assertRaises(TimeoutError) as captured:
                with control.PrepareProgress(Path(temp), fail_save, lambda _: None, {}):
                    raise original
            self.assertIs(captured.exception, original)

    def test_b1_build_and_b2_prepare_never_builds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def save(path, data):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
            sync = lambda _: None
            built = control.build(root, 'a' * 64, save, sync)
            self.assertEqual(built['signature_status'], 'verified')
            import importlib.util
            copydir = root / 'copied-sources'; copydir.mkdir()
            scripts = Path(control.__file__).parent
            for filename in ('recovery_panic_control.py', 'panic-source-preflight.py', 'recovery_nvram_panic.py'):
                (copydir / filename).write_bytes((scripts / filename).read_bytes())
            spec = importlib.util.spec_from_file_location('private_control', copydir / 'recovery_panic_control.py')
            copied = importlib.util.module_from_spec(spec); spec.loader.exec_module(copied)
            self.assertEqual(copied.validate_built(root, 'a' * 64), built)
            calls = []
            def observe(binary, nonce, directory, facts, *, env, on_timeout):
                self.assertEqual(env, control.CHILD_ENV)
                calls.append('observe')
            def compile_only(binary, nonce, directory, *, env, on_timeout):
                calls.append('compile_only'); return True
            prepared = control.prepare(root, 'a' * 64, save, sync, observe=observe, compile_only=compile_only)
            self.assertEqual(calls, ['observe', 'compile_only'])
            self.assertEqual(prepared['helper_sha256'], built['helper_sha256'])
            self.assertEqual(control.validate_prepared(root, 'a' * 64, prepared), root / 'panic-control' / 'helper')

    def test_b2_rejects_tampered_or_missing_build_before_observation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def save(path, data):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
            sync = lambda _: None
            control.build(root, 'a' * 64, save, sync)
            private = root / 'panic-control'
            paths = [private / 'built.json', private / 'helper.c', private / 'helper']
            originals = {path: path.read_bytes() for path in paths}
            calls = []
            def observe(*args, **kwargs): calls.append('observe')
            def compile_only(*args, **kwargs): calls.append('compile_only'); return True
            for kind in ('built_missing', 'built_modified', 'source_modified', 'binary_modified', 'wrong_nonce', 'binary_mode'):
                with self.subTest(kind=kind):
                    if kind == 'built_missing': paths[0].unlink()
                    elif kind == 'built_modified': paths[0].write_bytes(b'{}')
                    elif kind == 'source_modified': paths[1].write_bytes(b'wrong')
                    elif kind == 'binary_modified': paths[2].write_bytes(b'wrong')
                    elif kind == 'binary_mode': paths[2].chmod(0o755)
                    with self.assertRaises((ValueError, OSError)):
                        control.prepare(root, 'b' * 64 if kind == 'wrong_nonce' else 'a' * 64,
                                        save, sync, observe=observe, compile_only=compile_only)
                    self.assertEqual(calls, [])
                    self.assertEqual(__import__('json').loads((private / 'prepare-failure.json').read_text())['stage'], 'verify_build')
                    for path in paths:
                        if not path.exists() or path.read_bytes() != originals[path]: path.write_bytes(originals[path])
                        path.chmod(0o700 if path.name == 'helper' else 0o600)
                    (private / 'prepare-failure.json').unlink()

    def test_timeout_capture_is_bounded_private_and_preserves_timeout(self):
        preflight = control.load_preflight()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            callback_pids = []
            calls = []
            actual_command = control._timeout_command
            def benign_command(argv, directory, label, budget, timeout):
                calls.append((argv, label, budget, timeout))
                return actual_command([sys.executable, '-c', 'import sys; sys.stdout.write("x" * 40000)'],
                                      directory, label, budget, timeout)
            def capture(child):
                callback_pids.append(child.pid)
                control.capture_timeout(child, root)
                self.assertIsNone(child.poll())
            with patch.object(control, '_timeout_command', benign_command), self.assertRaises(TimeoutError):
                preflight.command([sys.executable, '-c', 'import time; time.sleep(10)'], root, 'target',
                                  timeout=0.05, env=control.CHILD_ENV, on_timeout=capture)
            self.assertEqual(len(callback_pids), 1)
            diagnostic = __import__('json').loads((root / 'timeout-diagnostic.json').read_text())
            self.assertIn(diagnostic['ps_status'], ('ok', 'failed', 'timeout', 'limit', 'unavailable'))
            self.assertEqual(diagnostic['profiler'], 'spindump')
            self.assertEqual(diagnostic['profiler_deadline_seconds'], 10)
            self.assertGreaterEqual(diagnostic['elapsed_ms'], 0)
            self.assertEqual(diagnostic['spindump_status'], 'limit')
            self.assertEqual(calls[1], (['/usr/sbin/spindump', str(callback_pids[0]), '1', '10', '-onlyTarget',
                                        '-noSymbolicate', '-noBinary', '-noFile'], 'spindump', 25536, 10))
            self.assertEqual((calls[0][1], calls[0][2], calls[0][3]), ('ps', 65536, 2))
            self.assertEqual(calls[0][0], ['/bin/ps', '-p', str(callback_pids[0]), '-o',
                                          'pid=,state=,wchan=,comm=,etime=,time=,pcpu='])
            paths = [root / ('timeout-' + kind + '.' + channel) for kind in ('ps', 'spindump') for channel in ('stdout', 'stderr')]
            self.assertEqual(sum(path.stat().st_size for path in paths if path.exists()), 65536)
            for path in paths:
                if path.exists(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_scope_requires_distinct_valid_boots_and_exact_fields(self):
        scope = {'binding': '12/1/' + 'a' * 40, 'nonce': 'b' * 64,
                 'baseline': 'AAAAAAAA-1111-1111-1111-111111111111',
                 'debug_boot_uuid': 'BBBBBBBB-2222-2222-2222-222222222222', 'source_identity': 'c' * 64}
        control.validate_scope(scope)
        for bad in ({**scope, 'debug_boot_uuid': scope['baseline']}, {**scope, 'nonce': 'bad'}, {**scope, 'extra': 1}):
            with self.assertRaises(ValueError): control.validate_scope(bad)

    def test_imported_preflight_uses_fixed_child_environment(self):
        preflight = control.load_preflight()
        args = preflight.helper_source('a' * 64)
        self.assertIn('vz_nonce_' + 'a' * 64, args)
        with self.assertRaises(ValueError): preflight.helper_source('invalid')
        self.assertNotIn('GITHUB_TOKEN', control.CHILD_ENV)

    def test_child_does_not_inherit_parent_token(self):
        previous = os.environ.get('GITHUB_TOKEN')
        os.environ['GITHUB_TOKEN'] = 'private-test-token'
        try:
            child = subprocess.run([sys.executable, '-c', 'import os; print(os.getenv("GITHUB_TOKEN", "absent"))'],
                                   env=control.CHILD_ENV, capture_output=True, check=True)
            self.assertEqual(child.stdout, b'absent\n')
        finally:
            if previous is None: del os.environ['GITHUB_TOKEN']
            else: os.environ['GITHUB_TOKEN'] = previous

    def test_once_record_is_exclusive_and_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            control.once_record(root, 'intent.json', {'a': 1}, lambda _: None)
            self.assertEqual((root / 'intent.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                control.once_record(root, 'intent.json', {'a': 2}, lambda _: None)

    def test_same_children_wait_past_timeout_without_kill(self):
        with tempfile.TemporaryDirectory() as temp:
            code = 'import time; time.sleep(0.16)'
            a = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            b = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            start = time.monotonic()
            result = control.wait_same_children(a, b, Path(temp), interval=0.03)
            self.assertGreaterEqual(time.monotonic() - start, 0.1)
            self.assertEqual((result['tracer_exit'], result['helper_exit']), (0, 0))
            self.assertGreaterEqual(result['wait_intervals'], 1)

    def test_interrupted_selector_and_wait_reap_same_children(self):
        import selectors
        class BrokenSelector(selectors.DefaultSelector):
            def select(self, timeout=None):
                raise KeyboardInterrupt()
        class InterruptedWait:
            def __init__(self, child):
                self.child = child
                self.stdout, self.stderr = child.stdout, child.stderr
                self.failed = False
            def poll(self): return self.child.poll()
            def wait(self, timeout=None):
                if not self.failed:
                    self.failed = True
                    raise InterruptedError()
                return self.child.wait(timeout=timeout)
        with tempfile.TemporaryDirectory() as temp:
            child = subprocess.Popen([sys.executable, '-c', 'import time; print("x",flush=True); time.sleep(0.15)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            other = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.15)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            faults = []
            start = time.monotonic()
            result = control.wait_same_children(InterruptedWait(child), other, Path(temp), interval=0.03,
                                                selector_factory=BrokenSelector, on_fault=faults.append)
            self.assertGreaterEqual(time.monotonic() - start, 0.1)
            self.assertEqual((result['tracer_exit'], result['helper_exit']), (0, 0))
            self.assertGreaterEqual(result['ownership_faults'], 2)
            self.assertTrue(all(code == 1 for code in faults))

    def test_failed_register_and_read_continue_same_children(self):
        import selectors
        class BrokenRegister(selectors.DefaultSelector):
            def register(self, *args, **kwargs): raise OSError('unavailable')
        first = [True]
        def intermittent(fd, size):
            if first[0]:
                first[0] = False
                raise InterruptedError()
            return os.read(fd, size)
        with tempfile.TemporaryDirectory() as temp:
            child = subprocess.Popen([sys.executable, '-c', 'import time; print("trace",flush=True); time.sleep(0.12)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            other = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.12)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = control.wait_same_children(child, other, Path(temp), interval=0.03,
                                                selector_factory=BrokenRegister, read_fn=intermittent)
            self.assertGreaterEqual(result['ownership_faults'], 2)
            self.assertEqual((result['tracer_exit'], result['helper_exit']), (0, 0))

    def test_double_selector_failure_still_drains_bounded_pipe(self):
        import selectors
        class BrokenSelector(selectors.DefaultSelector):
            def select(self, timeout=None): raise OSError('unavailable')
        def broken_fallback(*args): raise OSError('unavailable')
        with tempfile.TemporaryDirectory() as temp:
            child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdout.write("x"*100000)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            other = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = control.wait_same_children(child, other, Path(temp), interval=0.01,
                                                selector_factory=BrokenSelector, fallback_select=broken_fallback)
            self.assertTrue(result['output_overflow'])
            self.assertEqual((result['tracer_exit'], result['helper_exit']), (0, 0))
            self.assertGreater(result['ownership_faults'], 0)

    def test_release_once_after_ack_and_fresh_boot(self):
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.exit(0 if sys.stdin.buffer.read(1) == b"G" else 3)'], stdin=subprocess.PIPE)
        steps = []
        try:
            result = control.release_after_ack(child, lambda _: steps.append('ack') or True, {},
                                               lambda: 'B', 'B', lambda: steps.append('intent'))
            self.assertEqual((result, steps), ('released', ['ack', 'intent']))
            self.assertEqual(child.wait(timeout=2), 0)
        finally:
            child.stdin.close()
            if child.poll() is None: child.kill(); child.wait(timeout=2)

    def test_wait_logs_are_private_under_permissive_umask(self):
        with tempfile.TemporaryDirectory() as temp:
            old = os.umask(0o022)
            try:
                a = subprocess.Popen([sys.executable, '-c', 'print("trace")'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                b = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                control.wait_same_children(a, b, Path(temp), interval=0.1)
                self.assertEqual({p.stat().st_mode & 0o777 for p in Path(temp).iterdir()}, {0o600})
            finally:
                os.umask(old)

    def test_wait_drains_even_if_log_is_not_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = root / 'tracer.stdout'
            existing.write_bytes(b'unchanged')
            existing.chmod(0o644)
            a = subprocess.Popen([sys.executable, '-c', 'print("trace")'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            b = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = control.wait_same_children(a, b, root, interval=0.1)
            self.assertTrue(result['output_overflow'])
            self.assertEqual((result['tracer_exit'], result['helper_exit']), (0, 0))
            self.assertEqual(existing.read_bytes(), b'unchanged')

    def test_wait_drains_and_bounds_output(self):
        with tempfile.TemporaryDirectory() as temp:
            a = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdout.write("x"*100000)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            b = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = control.wait_same_children(a, b, Path(temp), interval=0.1)
            self.assertTrue(result['output_overflow'])
            self.assertEqual((result['tracer_exit'], result['helper_exit']), (0, 0))
            self.assertLessEqual(sum(p.stat().st_size for p in Path(temp).iterdir()), control.MAX_OUTPUT)

    def test_false_ack_does_not_release_child(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.exit(0 if sys.stdin.buffer.read(1) == b"G" else 3)'], stdin=subprocess.PIPE)
            try:
                result = control.release_after_ack(child, lambda _: False, {}, lambda: 'B', 'B', lambda: None)
                self.assertEqual(result, 'not_released')
                self.assertIsNone(child.poll())
                child.stdin.close()
                self.assertEqual(child.wait(timeout=2), 3)
            finally:
                if child.poll() is None: child.kill(); child.wait(timeout=2)

if __name__ == '__main__': unittest.main()
