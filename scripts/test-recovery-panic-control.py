import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import recovery_panic_control as control


class PanicControl(unittest.TestCase):
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
            def observe(binary, nonce, directory, facts, *, env):
                self.assertEqual(env, control.CHILD_ENV)
                calls.append('observe')
            def compile_only(binary, nonce, directory, *, env):
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
