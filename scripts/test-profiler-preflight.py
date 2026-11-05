import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import selectors
import unittest

spec = importlib.util.spec_from_file_location('profiler', Path(__file__).with_name('profiler-preflight.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Profiler(unittest.TestCase):
    def test_owned_python_target_stops_only_after_one_byte(self):
        child = r.start_target()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(3))
                self.assertEqual(r.os.read(child.stdout.fileno(), 7), b'READY\n')
            self.assertIsNone(child.poll())
        finally:
            cleanup = r.stop_target(child)
        self.assertEqual(cleanup, 'reaped')
        self.assertEqual(child.returncode, 0)

    def test_report_requires_success_target_pid_and_stack_frames(self):
        report = b'Process: Python [123]\nReport Version: 55\nThread 0x1:\n  4 ??? (in Python) [0x1234]\n'
        self.assertEqual(r.report_status('ok', report, 123), 'verified')
        alternate = b'PID: 123\nThread 1:\n  1 ??? [0xabc]\n'
        self.assertEqual(r.report_status('ok', alternate, 123), 'verified')
        for status, data, pid in [('timeout', report, 123), ('ok', report, 456),
                                  ('ok', b'Sampling process 123 for 1 second\n', 123),
                                  ('ok', b'PID: 123\n', 123), ('ok', report * 1000, 123),
                                  ('ok', alternate + b'PID: 456\n', 123)]:
            self.assertEqual(r.report_status(status, data, pid), 'unverified')

    def test_public_summary_retains_only_filtered_facts_and_ciphertext(self):
        cipher = b'synthetic encrypted bytes'
        state = {'status': 'passed', 'cleanup': 'reaped', 'report_status': 'verified',
                 'context': {'run_id': '123', 'attempt': '1', 'head_sha': 'a' * 40, 'token': 'private'},
                 'sources': {'preflight_sha256': 'b' * 64, 'control_sha256': 'c' * 64,
                             'guard_sha256': 'e' * 64, 'reports_sha256': 'f' * 64, 'raw': 'private'},
                 'envelope': {'cert_fingerprint': 'd' * 64, 'cipher_sha256': hashlib.sha256(cipher).hexdigest(),
                              'ciphertext': base64.b64encode(cipher).decode(), 'raw': 'private'}, 'raw': 'private'}
        summary = r.public_summary(state)
        self.assertEqual(summary['status'], 'passed')
        self.assertEqual(summary['context'], {'run_id': '123', 'attempt': '1', 'head_sha': 'a' * 40})
        self.assertEqual(summary['sources'], {'preflight_sha256': 'b' * 64, 'control_sha256': 'c' * 64,
                                             'guard_sha256': 'e' * 64, 'reports_sha256': 'f' * 64})
        self.assertNotIn('private', json.dumps(summary))
        for group, keys in (('context', ('run_id', 'attempt', 'head_sha')),
                            ('sources', ('preflight_sha256', 'control_sha256', 'guard_sha256', 'reports_sha256'))):
            for key in keys:
                original = state[group].pop(key)
                self.assertEqual(r.public_summary(state)['status'], 'failed')
                state[group][key] = 'invalid'
                self.assertEqual(r.public_summary(state)['status'], 'failed')
                state[group][key] = original
        state['report_status'] = 'unverified'
        self.assertEqual(r.public_summary(state)['status'], 'unverified')
        state['envelope']['cipher_sha256'] = '0' * 64
        self.assertEqual(r.public_summary(state)['status'], 'failed')
        self.assertNotIn('envelope', r.public_summary(state))


if __name__ == '__main__':
    unittest.main()
