import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest

spec = importlib.util.spec_from_file_location('cf_spawn', Path(__file__).with_name('cf-spawn-control.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class CFSpawn(unittest.TestCase):
    def test_case_validation(self):
        for case in ('direct_off', 'direct_on', 'launchd_off', 'launchd_on'):
            self.assertTrue(m.valid_case(case))
        for case in ('direct_foo', '../direct_on', '', 'launchd_on/../../x'):
            self.assertFalse(m.valid_case(case))

    def test_public_facts_drop_unknown_and_raw(self):
        result = m.public_command({'status': 'ok', 'exit': 0, 'bytes': 4,
                                   'stdout': 'private output', 'error': 'private detail'})
        self.assertEqual(result, {'status': 'ok', 'exit': 0, 'bytes': 4})
        self.assertNotIn('private', str(result))
        self.assertEqual(m.public_command({'status': 'private detail', 'exit': True, 'bytes': -1}),
                         {'status': 'invalid', 'exit': None, 'bytes': None})

    def test_success_requires_zero_exit_and_bounded_byte_count(self):
        for fact in ({'status': 'ok', 'exit': 1, 'bytes': 1},
                     {'status': 'ok', 'exit': None, 'bytes': 1},
                     {'status': 'ok', 'exit': 0, 'bytes': None},
                     {'status': 'ok', 'exit': 0, 'bytes': 65537}):
            self.assertEqual(m.public_command(fact)['status'], 'invalid')
        self.assertEqual(m.public_command({'status': 'ok', 'exit': 0, 'bytes': 0})['status'], 'ok')

    def test_only_explicit_single_case_is_selected(self):
        for case in ('direct_off', 'direct_on', 'launchd_off', 'launchd_on'):
            self.assertEqual(m.selected_case({'CF_SPAWN_CASE': case}), case)
        for environment in ({}, {'CF_SPAWN_CASE': ''}, {'CF_SPAWN_CASE': 'all'}, {'CF_SPAWN_CASE': '../direct_on'}):
            with self.assertRaises(ValueError): m.selected_case(environment)

    def test_case_result_whitelists_nested_data(self):
        value = {'case': 'direct_off', 'child_pid': 123, 'cwd_is_root': True, 'stage': 'clang', 'sigchld': {'disposition': 'default', 'blocked': False, 'raw': 'secret'}, 'sigchld_after': {'disposition': 'ignored', 'blocked': True, 'raw': 'secret'}, 'getter': {'status': 'skipped', 'bytes': None, 'sha256': None, 'raw': 'secret'},
                 'commands': {name: {'status': 'ok', 'exit': 0, 'bytes': 3, 'stdout': 'secret'} for name in ('echo', 'clang', 'dtrace_version')},
                 'probe_status': 'ok', 'probe': {'ready_count': 1, 'function_exact': True, 'raw': 'secret'}, 'token': 'secret'}
        result = m.public_result(value, 'direct_off')
        self.assertNotIn('secret', str(result))
        self.assertEqual(result['probe']['ready_count'], 1)
        self.assertEqual((result['stage'], result['cwd_is_root'], result['sigchld']), ('clang', True, {'disposition': 'default', 'blocked': False}))
        self.assertEqual(result['sigchld_after'], {'disposition': 'ignored', 'blocked': True})
        with self.assertRaises(ValueError): m.public_result(value, 'direct_on')

    def test_private_progress_is_atomic_and_redacted_when_reexposed(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value = {'case': 'direct_on', 'child_pid': 345, 'stage': 'getter',
                     'sigchld': {'disposition': 'ignored', 'blocked': True},
                     'getter': {'status': 'pending', 'bytes': None, 'sha256': None, 'raw': 'secret'},
                     'commands': {}, 'probe': {}, 'probe_status': 'pending'}
            m.save_progress(root, value)
            saved = json.loads((root / 'progress.json').read_text())
            visible = m.public_result(saved, 'direct_on')
            self.assertEqual((visible['stage'], visible['getter']['status']), ('getter', 'pending'))
            self.assertEqual(visible['probe_status'], 'pending')
            self.assertNotIn('secret', str(visible))
            self.assertEqual((root / 'progress.json').stat().st_mode & 0o777, 0o600)

    def test_sigchld_observation_is_readonly(self):
        import signal
        before = signal.getsignal(signal.SIGCHLD)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        facts = m.sigchld_facts()
        self.assertIn(facts['disposition'], ('default', 'ignored', 'callable', 'unknown'))
        self.assertIn(facts['blocked'], (True, False, None))
        self.assertEqual(signal.getsignal(signal.SIGCHLD), before)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), mask)

    def test_python_identity_pins_observed_owner_and_inode(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp).resolve() / 'python-fixture'
            executable.write_bytes(b'fixture')
            executable.chmod(0o500)
            identity = m.python_identity(executable)
            self.assertEqual(identity['uid'], os.geteuid())
            self.assertEqual(identity['ino'], executable.stat().st_ino)
            self.assertEqual(identity['sha256'], m.sha(b'fixture'))
            executable.rename(Path(tmp).resolve() / 'old')
            executable.write_bytes(b'fixture'); executable.chmod(0o500)
            self.assertNotEqual(m.python_identity(executable), identity)
            executable.chmod(0o522)
            with self.assertRaises(ValueError): m.python_identity(executable)
            executable.chmod(0o400)
            with self.assertRaises(ValueError): m.python_identity(executable)

    def test_direct_child_starts_at_root(self):
        with tempfile.TemporaryDirectory() as temp:
            argv = m.direct_argv([sys.executable, '-c', 'import os; print(os.getcwd())'])
            result = m.run_command(argv, Path(temp), 'cwd', timeout=2)
            self.assertEqual(result['status'], 'ok')
            self.assertEqual((Path(temp) / 'cwd.stdout').read_bytes(), b'/\n')

    def test_real_owned_child_command(self):
        with tempfile.TemporaryDirectory() as temp:
            status = m.run_command([sys.executable, '-c', 'print("test")'], Path(temp), 'fixture', timeout=2)
            self.assertEqual(m.public_command(status), {'status': 'ok', 'exit': 0, 'bytes': 5})

if __name__ == '__main__': unittest.main()
