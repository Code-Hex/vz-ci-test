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

import nonce_usdt as usdt

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('usdt_candidate', HERE / 'usdt_feasibility.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class Feasibility(unittest.TestCase):
    def test_ready_requires_owned_pid(self):
        f.parse_ready(b'HELPER_READY 123\n', 123)
        with self.assertRaises(f.GateFailure): f.parse_ready(b'HELPER_READY 124\n', 123)

    def test_helper_wraps_the_shared_function_with_only_o_and_q(self):
        spec = usdt.ProbeSpec('a' * 64)
        source = f.helper_source(spec)
        self.assertEqual(source.count(usdt.function_source(spec)), 1)
        self.assertIn(('    ' + spec.function + '();\n').encode(), source)
        self.assertIn(b"value != 'O'", source)
        self.assertIn(b"value != 'Q'", source)
        self.assertNotIn(b"value != 'G'", source)

    def test_final_output_requires_exactly_one_cli_lf_and_unchanged_helper(self):
        ready = b'HELPER_READY 123\n'
        hit = b'HIT 123 vzobsaaaaaaaaaaaaaaaap123 helper vz_nonce_' + b'a' * 64 + b' observe aaaaaaaaaaaaaaaa\n'
        tracer = b'TRACER_READY\n' + hit
        helper = ready + b'HELPER_RETURNED\n'
        f.validate_final_output(tracer + b'\n', helper, ready, hit)
        for extra in (b'', b'\n\n', b'x', hit + b'\n', b'\r\n'):
            with self.subTest(extra=extra):
                with self.assertRaises(f.GateFailure): f.validate_final_output(tracer + extra, helper, ready, hit)
        for changed in (helper + b'\n', helper.replace(b'\n', b'\r\n')):
            with self.assertRaises(f.GateFailure): f.validate_final_output(tracer + b'\n', changed, ready, hit)

    def test_compile_only_and_nonfaulting_programs_share_exact_bound_identity(self):
        probe = usdt.ProbeSpec('a' * 64).bind(123)
        predicate = ' /pid == 123 && arg0 == 0xaaaaaaaaaaaaaaaa/ '
        self.assertEqual(f.panic_compile_command(probe), ['/usr/sbin/dtrace', '-w', '-e', '-n', probe.selector + predicate + '{ panic(); }'])
        command = f.tracer_command(probe)
        self.assertEqual(command[:6], ['/usr/sbin/dtrace', '-q', '-x', 'switchrate=10hz', '-n', command[-1]])
        self.assertIn(probe.selector + predicate, command[-1])
        for flag in ('-a', '-p', '-c', '-W', '-Z', '-w', '-e'):
            self.assertNotIn(flag, command)
        self.assertNotIn('panic()', command[-1])

    def test_compile_exit_timeout_and_signal_keep_o_unsent_and_reap_owned_children(self):
        spec = usdt.ProbeSpec('a' * 64)
        cases = (('command_exit', 'import sys; sys.exit(7)', 1),
                 ('deadline', 'import time; time.sleep(60)', .03),
                 ('interrupted', 'import os,signal,time; os.kill(os.getppid(),signal.SIGINT); time.sleep(60)', 1))
        for reason, compiler, seconds in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(prefix='compile-boundary-', dir=HERE) as directory:
                directory = Path(directory)
                received = directory / 'received'
                helper = directory / 'helper'
                helper.write_text('#!' + sys.executable + '\nimport os,sys\nfrom pathlib import Path\n'
                                  'print("HELPER_READY " + str(os.getpid()),flush=True)\n'
                                  'value=sys.stdin.buffer.read(1)\n'
                                  'Path(' + repr(str(received)) + ').write_bytes(value)\n')
                helper.chmod(0o700)
                state = f.State()
                def run_command(argv, name, current, _seconds):
                    probe = spec.bind(current.report['helper_pid'])
                    if name == 'listing':
                        raw = 'ID PROVIDER MODULE FUNCTION NAME\n7 ' + ' '.join(probe.fields) + '\n'
                        return f.command([sys.executable, '-c', 'print(' + repr(raw) + ',end="")'], name, current)
                    self.assertEqual(name, 'panic_compile')
                    self.assertEqual(argv, f.panic_compile_command(probe))
                    return f.command([sys.executable, '-c', compiler], name, current, seconds)
                previous = f.install_signal_handlers()
                try:
                    with self.assertRaises(f.GateFailure) as caught:
                        f.execute(directory, spec, state, run_command=run_command)
                finally: f.restore_signal_handlers(previous)
                self.assertEqual(caught.exception.reason, reason)
                report = f.public_report(state.report)
                self.assertEqual((report['stage'], report['o_attempts'], report['o_written'], report['cleanup']),
                                 ('compile_panic', 0, False, 'reaped'))
                self.assertFalse(received.exists())
                self.assertIsNone(report['tracer_pid'])
                self.assertIsNotNone(report['commands']['panic_compile']['exit'])
                self.assertIsNotNone(report['commands']['helper']['exit'])
                self.assertFalse(report['commands']['helper']['output_complete'])

    def test_passed_report_requires_compile_command_and_program_hash(self):
        command = {'exit': 0, 'stdout_bytes': 0, 'stderr_bytes': 0, 'stdout_sha256': 'a' * 64,
                   'stderr_sha256': 'a' * 64, 'output_complete': True}
        report = {**f.initial_report(), 'status': 'passed', 'stage': 'completed', 'root': True, 'kernel_matched': True,
                  'system': 'Darwin', 'machine': 'x86_64', 'context': {'run': '123', 'attempt': '1', 'sha': 'a' * 40,
                  'repository': 'Code-Hex/vz-ci-test', 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
                  'runner_environment': 'github-hosted'}, 'helper_pid': 123, 'tracer_pid': 124, 'listing_rows': 1,
                  'o_attempts': 1, 'hit_count': 1, 'o_written': True, 'q_written': True, 'helper_returned': True,
                  'cleanup': 'reaped', 'hashes': {name: 'a' * 64 for name in f.HASHES},
                  'commands': {name: dict(command) for name in f.COMMANDS}}
        self.assertEqual(f.public_report(report)['status'], 'passed')
        self.assertEqual(len(report['commands']), 10)
        self.assertEqual(len(report['hashes']), 12)
        for change in ({'commands': {key: item for key, item in report['commands'].items() if key != 'panic_compile'}},
                       {'hashes': {key: item for key, item in report['hashes'].items() if key != 'panic_program'}},
                       {'hashes': {key: item for key, item in report['hashes'].items() if key != 'usdt_core'}},
                       {'commands': {**report['commands'], 'panic_compile': {**command, 'output_complete': False}}},
                       {'commands': {**report['commands'], 'panic_compile': {**command, 'exit': 7}}}):
            with self.assertRaises(f.GateFailure): f.public_report({**report, **change})

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
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1]).parent))
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
            spec = usdt.ProbeSpec('a' * 64)
            f.build(Path(directory), spec, os.uname().machine, state)
            self.assertTrue(all(item['exit'] == 0 for item in state.report['commands'].values()))
            self.assertEqual(set(state.report['commands']), {'header', 'compile', 'sign', 'verify'})
            self.assertEqual(state.report['hashes']['helper_binary'], hashlib.sha256((Path(directory) / 'helper').read_bytes()).hexdigest())
            self.assertIsNone(state.report['helper_pid'])
            self.assertIsNone(state.report['tracer_pid'])


if __name__ == '__main__': unittest.main()
