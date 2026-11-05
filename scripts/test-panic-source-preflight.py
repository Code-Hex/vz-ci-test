import importlib.util
from pathlib import Path
import unittest
import tempfile
import sys
import os
import subprocess
import time

import nonce_usdt as usdt

spec = importlib.util.spec_from_file_location('preflight', Path(__file__).with_name('panic-source-preflight.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Preflight(unittest.TestCase):
    def test_usdt_g_wrapper_uses_shared_fullnonce_and_prints_owned_ready(self):
        spec = usdt.ProbeSpec('a' * 64)
        source = p.helper_source(spec.nonce, control_kind='usdt-v1')
        self.assertEqual(source.count(usdt.function_source(spec).decode()), 1)
        self.assertIn('HELPER_READY %ld\\n', source)
        self.assertIn("c != 'G'", source)
        self.assertNotIn("c != 'O'", source)
        with self.assertRaises(ValueError): p.helper_source(spec.nonce, control_kind='unknown')

    def test_usdt_commands_bind_exact_owned_probe_without_attach(self):
        probe = usdt.ProbeSpec('a' * 64).bind(123)
        self.assertEqual(p.usdt_command(probe, 'compile'), ['/usr/sbin/dtrace', '-w', '-e', '-n', probe.selector + probe.predicate + '{ panic(); }'])
        actual = p.usdt_command(probe, 'fire')
        self.assertEqual(actual[:6], ['/usr/sbin/dtrace', '-w', '-q', '-x', 'switchrate=10hz', '-n'])
        self.assertIn(probe.selector + probe.predicate + '{ panic(); }', actual[-1])
        safe = p.usdt_command(probe, 'observe')
        self.assertNotIn('-w', safe)
        self.assertNotIn('panic()', safe[-1])
        for command in (actual, safe, p.usdt_command(probe, 'compile')):
            for flag in ('-p', '-c', '-W', '-Z', '-a'): self.assertNotIn(flag, command)
        with self.assertRaises(ValueError): p.usdt_command(probe, 'arbitrary')

    def test_native_owned_helper_ready_is_exact_and_bounded(self):
        programs = ('import os,sys; print("HELPER_READY "+str(os.getpid()),flush=True); sys.stdin.read(1)',
                    'import sys; print("HELPER_READY 1",flush=True); sys.stdin.read(1)',
                    'import time; time.sleep(10)')
        for index, program in enumerate(programs):
            child = subprocess.Popen([sys.executable, '-c', program], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            try:
                if index == 0: p.read_helper_ready(child, time.monotonic()+1)
                else:
                    with self.assertRaises(ValueError if index == 1 else TimeoutError):
                        p.read_helper_ready(child, time.monotonic()+.05)
                self.assertIsNone(child.poll())
            finally:
                child.kill(); child.wait(timeout=2); child.stdin.close(); child.stdout.close()

    def test_usdt_compile_fixture_failure_never_sends_g_and_reaps_ready_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); helper=root/'helper'; pidfile=root/'pid'; received=root/'received'
            helper.write_text('#!'+sys.executable+'\nimport os,sys\nfrom pathlib import Path\n'
                'Path('+repr(str(pidfile))+').write_text(str(os.getpid()))\n'
                'print("HELPER_READY "+str(os.getpid()),flush=True)\n'
                'value=sys.stdin.buffer.read(1)\nPath('+repr(str(received))+').write_bytes(value)\n')
            helper.chmod(0o700)
            phases=[]
            def run_command(argv, directory, label, timeout, **kwargs):
                phases.append(label)
                probe=usdt.ProbeSpec('a'*64).bind(int(pidfile.read_text()))
                if label=='compile-listing':
                    program='print('+repr('ID PROVIDER MODULE FUNCTION NAME\n1 '+' '.join(probe.fields)+'\n')+',end="")'
                else:
                    self.assertEqual(argv,p.usdt_command(probe,'compile')); program='import sys; sys.exit(7)'
                return p.command([sys.executable,'-c',program],directory,label,timeout,**kwargs)
            self.assertFalse(p._compile_usdt(helper,'a'*64,root,deadline=time.monotonic()+2,run_command=run_command))
            self.assertEqual(phases,['compile-listing','panic-compile'])
            self.assertFalse(received.exists())
            with self.assertRaises(ProcessLookupError): os.kill(int(pidfile.read_text()),0)

    def test_usdt_observation_fixture_uses_ready_then_one_g_and_exact_fullnonce_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); helper=root/'helper'; pidfile=root/'pid'; received=root/'received'
            helper.write_text('#!'+sys.executable+'\nimport os,sys\nfrom pathlib import Path\n'
                'Path('+repr(str(pidfile))+').write_text(str(os.getpid()))\n'
                'print("HELPER_READY "+str(os.getpid()),flush=True)\n'
                'value=sys.stdin.buffer.read(1)\nPath('+repr(str(received))+').write_bytes(value)\n')
            helper.chmod(0o700)
            def run_command(argv,directory,label,timeout,**kwargs):
                probe=usdt.ProbeSpec('a'*64).bind(int(pidfile.read_text()))
                self.assertEqual(argv[-1],probe.selector)
                raw='ID PROVIDER MODULE FUNCTION NAME\n1 '+' '.join(probe.fields)+'\n'
                return p.command([sys.executable,'-c','print('+repr(raw)+',end="")'],directory,label,timeout,**kwargs)
            children=[]
            def start_tracer(argv,**kwargs):
                probe=usdt.ProbeSpec('a'*64).bind(int(pidfile.read_text()))
                self.assertNotIn('-w',argv); self.assertNotIn('panic()',argv[-1])
                line='HIT '+str(probe.pid)+' '+' '.join(probe.fields)+' '+probe.spec.argument
                program=('import time\nfrom pathlib import Path\nprint("READY",flush=True)\n'
                    'deadline=time.monotonic()+2\nwhile not Path('+repr(str(received))+').exists():\n'
                    ' if time.monotonic()>deadline: raise TimeoutError()\n time.sleep(.01)\nprint('+repr(line)+')\nprint()')
                child=subprocess.Popen([sys.executable,'-c',program],**kwargs); children.append(child); return child
            facts={}
            self.assertTrue(p._observe_usdt(helper,'a'*64,root,facts,deadline=time.monotonic()+3,
                                           run_command=run_command,start_tracer=start_tracer))
            self.assertEqual(received.read_bytes(),b'G')
            self.assertEqual((facts['ready_count'],facts['hit_count'],facts['helper_exit'],facts['tracer_exit']),(1,1,0,0))
            self.assertTrue(facts['provider_exact'] and facts['function_exact'] and facts['name_exact'])
            self.assertEqual(children[0].poll(),0)
            with self.assertRaises(ProcessLookupError): os.kill(int(pidfile.read_text()),0)

    def test_exact_probe_list(self):
        name = 'vz_nonce_' + 'a' * 64
        line = f'   ID PROVIDER MODULE FUNCTION NAME\n  123 pid456 helper {name} entry\n'
        self.assertEqual(p.parse_probe_list(line, 456, name), 'matched')
        self.assertEqual(p.parse_probe_list(line, 457, name), 'missing')
        self.assertEqual(p.parse_probe_list(line + line, 456, name), 'ambiguous')
        self.assertEqual(p.parse_probe_list(line.replace(' entry', ' return'), 456, name), 'missing')

    def test_helper_name_and_no_untrusted_source(self):
        source = p.helper_source('a' * 64)
        self.assertIn('vz_nonce_' + 'a' * 64, source)
        self.assertIn('read(STDIN_FILENO', source)
        with self.assertRaises(ValueError): p.helper_source('a;evil')

    def test_script_actions(self):
        safe = p.probe_script('a' * 64, False)
        compile_only = p.probe_script('a' * 64, True)
        self.assertNotIn('panic()', safe)
        self.assertIn('panic()', compile_only)
        self.assertIn(':entry', safe)
        self.assertIn('READY', safe)
        self.assertIn('HIT', safe)

    def test_command_bounds_both_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code, out = p.command([sys.executable, '-c', 'import sys; print("ok"); print("private", file=sys.stderr)'], root, 'small')
            self.assertEqual((code, out), (0, b'ok\n'))
            self.assertEqual((root / 'small.stderr').read_bytes(), b'private\n')
            with self.assertRaisesRegex(ValueError, 'output_limit'):
                p.command([sys.executable, '-c', 'import sys; sys.stderr.write("x" * 100000)'], root, 'large')
            self.assertLessEqual((root / 'large.stderr').stat().st_size, p.LIMIT)

    def test_timeout_callback_runs_before_child_cleanup_and_preserves_timeout(self):
        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            def capture(child):
                seen.append(child.poll() is None)
                raise RuntimeError('private error')
            with self.assertRaises(TimeoutError):
                p.command([sys.executable, '-c', 'import time; time.sleep(2)'], Path(tmp), 'timeout',
                          timeout=0.05, on_timeout=capture)
        self.assertEqual(seen, [True])

    def test_private_logs_ignore_umask_and_reject_symlinks(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = os.umask(0o022)
            try:
                p.command([sys.executable, '-c', 'print("ok")'], root, 'mode')
                self.assertEqual((root / 'mode.stdout').stat().st_mode & 0o777, 0o600)
                self.assertEqual((root / 'mode.stderr').stat().st_mode & 0o777, 0o600)
                (root / 'unsafe').symlink_to(root / 'mode.stdout')
                with self.assertRaises(OSError): p.open_private(root / 'unsafe', append=True)
                (root / 'mode.stdout').chmod(0o644)
                with self.assertRaises(OSError): p.open_private(root / 'mode.stdout', append=True)
            finally:
                os.umask(old)

    def test_command_uses_explicit_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = p.command([sys.executable, '-c', 'import os; print(os.getenv("GITHUB_TOKEN", "absent"))'],
                                  Path(tmp), 'environment', env={'PATH': '/usr/bin:/bin'})
            self.assertEqual((code, out), (0, b'absent\n'))

    def test_diagnostics_capture_actual_mismatch_without_raw_values(self):
        name = 'vz_nonce_' + 'a' * 64
        data = f'READY\nHIT pid456:helper:{name}:return\n'.encode()
        result = p.event_facts(data, 456, name)
        self.assertEqual(result, {'ready_count': 1, 'hit_count': 1, 'provider_exact': True,
                                  'function_exact': True, 'name_exact': False, 'nonempty_line_count': 2})
        self.assertNotIn(name, str(result))
        self.assertEqual(p.stderr_kind(b'dtrace: permission denied: secret'), 'permission')
        self.assertEqual(p.stderr_kind(b'dtrace: strange details'), 'other')
        self.assertEqual(p.stderr_kind(b''), 'empty')

    def test_public_result_is_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'result.json'
            old = __import__('os').umask(0o077)
            try: p.write_public(path, {'status': 'failed'})
            finally: __import__('os').umask(old)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(__import__('json').loads(path.read_text()), {'status': 'failed'})

    def test_probe_events_allow_only_surrounding_whitespace(self):
        name = 'vz_nonce_' + 'a' * 64
        hit = f'HIT pid456:helper:{name}:entry'.encode()
        self.assertTrue(p.events_valid(b'\n  READY\r\n\n  ' + hit + b'  \n\n', 456, name))
        for data in (b'READY\nunknown\n' + hit + b'\n', b'READY\n' + hit + b'\n' + hit + b'\n'):
            self.assertFalse(p.events_valid(data, 456, name))

    def test_events_only_exact_once_in_order(self):
        name = 'vz_nonce_' + 'a' * 64
        hit = f'HIT pid456:helper:{name}:entry\n'.encode()
        self.assertTrue(p.events_valid(b'READY\n' + hit, 456, name))
        for data in (hit + b'READY\n', b'READY\n' + hit + hit, b'READY\n',
                     b'READY\n' + hit + b'extra\n', b'READY\n' + hit.replace(b'pid456', b'pid457'),
                     b'READY\n' + hit.replace(name.encode(), b'other')):
            self.assertFalse(p.events_valid(data, 456, name))

if __name__ == '__main__': unittest.main()
