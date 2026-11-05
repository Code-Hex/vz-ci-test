import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import subprocess
import signal
import json
import time
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('usdt_candidate', HERE / 'usdt_feasibility.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class Feasibility(unittest.TestCase):
    def test_provider_header_and_nonce_argument_are_deterministic(self):
        provider, argument = f.identity('a' * 64)
        self.assertTrue(provider.endswith('p'))
        self.assertEqual(argument, 'a' * 16)
        self.assertTrue(f.validate_header(('#define ' + provider.upper() + '_OBSERVE(arg0) whatever\n').encode(), provider))
        for raw in (b'', b'#define FOREIGN_OBSERVE(arg0) x\n', b'\xff'):
            with self.assertRaises(f.GateFailure): f.validate_header(raw, provider)

    def test_listing_requires_all_matching_rows_to_be_owned_and_exact(self):
        provider, _ = f.identity('a' * 64)
        header = 'ID PROVIDER MODULE FUNCTION NAME\n'
        row = '7 ' + provider + '123 helper main observe\n'
        self.assertEqual(f.parse_listing((header + row).encode(), provider, 123), 1)
        for raw in ((header + row.replace('123', '124')).encode(), header.encode(), (header + row + row).encode(),
                    (header + row.replace('helper', 'foreign')).encode(), (header + row.replace('main', 'foreign')).encode()):
            with self.assertRaises(f.GateFailure): f.parse_listing(raw, provider, 123)

    def test_hit_and_ready_require_owned_pid_provider_and_exact_argument(self):
        provider, argument = f.identity('a' * 64)
        f.parse_ready(b'HELPER_READY 123\n', 123)
        line = ('HIT 123 ' + provider + '123 helper main observe ' + argument + '\n').encode()
        f.parse_hit(line, provider, argument, 123)
        for bad in (line.replace(b'HIT 123 ', b'HIT 124 '), line.replace(argument.encode(), b'0' * 16), line + b'extra\n'):
            with self.assertRaises(f.GateFailure): f.parse_hit(bad, provider, argument, 123)
        with self.assertRaises(f.GateFailure): f.parse_ready(b'HELPER_READY 124\n', 123)
        command = f.tracer_command(provider, argument, 123)
        self.assertFalse(any(flag in command for flag in ('-p', '-c', '-W', '-w', '-Z')))
        self.assertNotIn('panic(', command[-1])

    def test_final_output_requires_exactly_one_cli_lf_and_unchanged_helper(self):
        ready = b'HELPER_READY 123\n'
        hit = b'HIT 123 vzobsaaaaaaaaaaaaaaaap123 helper main observe aaaaaaaaaaaaaaaa\n'
        tracer = b'TRACER_READY\n' + hit
        helper = ready + b'HELPER_RETURNED\n'
        f.validate_final_output(tracer + b'\n', helper, ready, hit)
        for extra in (b'', b'\n\n', b'x', hit + b'\n', b'\r\n'):
            with self.subTest(extra=extra):
                with self.assertRaises(f.GateFailure): f.validate_final_output(tracer + extra, helper, ready, hit)
        for changed in (helper + b'\n', helper.replace(b'\n', b'\r\n')):
            with self.assertRaises(f.GateFailure): f.validate_final_output(tracer + b'\n', changed, ready, hit)

    def test_public_report_rejects_raw_and_context_rejects_untrusted_inputs(self):
        report = f.initial_report()
        self.assertEqual(f.public_report(report), report)
        with self.assertRaises(f.GateFailure): f.public_report({**report, 'raw': 'private'})
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REPOSITORY': 'Code-Hex/vz-ci-test',
               'GITHUB_REF': 'refs/heads/main', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_RUN_ID': '123',
               'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40}
        self.assertEqual(f.checked_context(env)['sha'], 'a' * 40)
        for changed in ({'GITHUB_EVENT_NAME': 'pull_request'}, {'GITHUB_SHA': 'private'}, {'GITHUB_RUN_ATTEMPT': '0'}):
            with self.assertRaises(f.GateFailure): f.checked_context({**env, **changed})

    def test_owned_child_killed_without_draining_never_claims_complete_output(self):
        state = f.State()
        child = f.Child([sys.executable, '-c', 'import sys; sys.stdin.read(1)'], state, stdin=True)
        child.stop()
        self.assertIsNotNone(child.facts()['exit'])
        self.assertFalse(child.facts()['output_complete'])

    def test_timeout_kills_only_the_owned_session_including_grandchild(self):
        state = f.State()
        program = ('import subprocess,sys,time; '
                   'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
                   'print(child.pid,flush=True); time.sleep(60)')
        child = f.Child([sys.executable, '-c', program], state)
        grandchild = int(child.line(2))
        try:
            with self.assertRaises(f.GateFailure): child.finish(.05)
        finally:
            child.stop()
        deadline = time.monotonic() + 2
        while True:
            result = subprocess.run(['/bin/ps', '-p', str(grandchild), '-o', 'state='], capture_output=True, text=True, timeout=1)
            if not result.stdout.strip() or result.stdout.strip().startswith('Z'): break
            if time.monotonic() >= deadline: self.fail('owned grandchild survived timeout')
            time.sleep(.05)
        self.assertFalse(child.facts()['output_complete'])

    def test_unverified_cleanup_produces_failed_public_json(self):
        report = {**f.initial_report(), 'status': 'passed', 'stage': 'completed', 'cleanup': 'unverified'}
        result = f.finalize_report(report)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['reason'], 'cleanup_unverified')

    def test_actual_term_and_int_cleanup_owned_session_and_restore_handlers(self):
        program = r"""import importlib.util,json,signal,sys
spec=importlib.util.spec_from_file_location('candidate',sys.argv[1]); f=importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
state=f.State(); prior={number:signal.getsignal(number) for number in (signal.SIGALRM,signal.SIGTERM,signal.SIGINT)}
previous=f.install_signal_handlers(); child=f.Child([sys.executable,'-c','import sys; sys.stdin.read(1)'],state,stdin=True)
try:
 print(child.process.pid,flush=True)
 child.finish(30)
except f.GateFailure as error:
 state.report['reason']=error.reason
finally:
 child.stop(); state.report['cleanup']='reaped' if child.process.poll() is not None else 'unverified'; f.restore_signal_handlers(previous)
public=f.finalize_report(state.report)
print(json.dumps({'status':public['status'],'reason':public['reason'],'cleanup':public['cleanup'],'exit':child.process.poll(),'restored':all(signal.getsignal(number)==handler for number,handler in prior.items())}),flush=True)
"""
        for number in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=number):
                controller = subprocess.Popen([sys.executable, '-c', program, str(HERE / 'usdt_feasibility.py')], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True)
                child_pid = int(controller.stdout.readline())
                try:
                    controller.send_signal(number)
                    raw, _ = controller.communicate(timeout=4)
                    self.assertEqual(controller.returncode, 0)
                    result = json.loads(raw)
                    self.assertEqual((result['status'], result['reason'], result['cleanup']), ('failed', 'interrupted', 'reaped'))
                    self.assertIsNotNone(result['exit'])
                    self.assertTrue(result['restored'])
                finally:
                    if controller.poll() is None: controller.kill(); controller.wait(timeout=2)
                    try: os.killpg(child_pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    controller.stdout.close()

    @unittest.skipUnless(sys.platform == 'darwin', 'Apple toolchain build only')
    def test_actual_header_compile_and_adhoc_sign_without_running_helper(self):
        with tempfile.TemporaryDirectory(prefix='build-test-', dir=HERE) as directory:
            state = f.State()
            provider, argument = f.identity('a' * 64)
            f.build(Path(directory), provider, argument, os.uname().machine, state)
            self.assertTrue(all(item['exit'] == 0 for item in state.report['commands'].values()))
            self.assertEqual(set(state.report['commands']), {'header', 'compile', 'sign', 'verify'})
            self.assertEqual(state.report['hashes']['helper_binary'], hashlib.sha256((Path(directory) / 'helper').read_bytes()).hexdigest())
            self.assertIsNone(state.report['helper_pid'])
            self.assertIsNone(state.report['tracer_pid'])


if __name__ == '__main__': unittest.main()
