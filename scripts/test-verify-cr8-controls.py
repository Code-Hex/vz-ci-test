import importlib.util
from pathlib import Path
import unittest
import os
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("verify", Path(__file__).with_name("verify-cr8-controls.py"))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def fact(api, result=0, arg0=0, arg1=0, arg2=0, edge="fact"):
    return dict(api=api, edge=edge, result=result, arg0=arg0, arg1=arg1, arg2=arg2)


class Controls(unittest.TestCase):
    def test_gates_only_facts(self):
        self.assertTrue(verify.is_gate(fact("run_ready")))
        self.assertFalse(verify.is_gate(fact("run_ready", edge="released")))
        self.assertFalse(verify.is_gate(fact("not_ready")))

    def test_success_and_wrong_reason(self):
        for phase, reason, length, name in [("cpuid", 10, 2, "sentinel_cpuid_verified"), ("hlt", 12, 1, "sentinel_hlt_verified")]:
            records = [fact("guest_observation", arg0=165, arg1=263, arg2=length), fact(name, arg0=reason, arg1=263, arg2=length), fact("process_result", arg2=1)]
            self.assertEqual(verify.classify(phase, records, 0, False), "success")
            records[1]["arg0"] = 1
            self.assertEqual(verify.classify(phase, records, 0, False), "failure")

    def test_early_interrupt_retry_requires_clean_exit(self):
        records = [fact("guest_observation", arg0=0, arg1=256, arg2=3), fact("guest_not_established", 77, 1, 256, 3), fact("process_result", 77, 77, 0, 0)]
        self.assertEqual(verify.classify("hlt", records, 77, False), "retry")
        self.assertEqual(verify.classify("cpuid", records, 77, False), "retry")
        records[-1]["arg1"] = 2
        self.assertEqual(verify.classify("hlt", records, 77, False), "failure")

    def test_timer_values_and_activity(self):
        for phase, rip, activity, name in [("timer-spin", 263, 0, "sentinel_spin_verified"), ("timer-hlt", 264, 1, "sentinel_hlt_timer_verified")]:
            records = [fact("guest_observation", arg0=165, arg1=rip, arg2=0), fact(name, arg0=52, arg1=rip, arg2=0), fact("timer_guest_state", arg0=52, arg1=rip, arg2=activity), fact("phase_result", arg1=1), fact("process_result", arg2=1)]
            self.assertEqual(verify.classify(phase, records, 0, False), "success")
            records[2]["arg2"] = 1 - activity
            self.assertEqual(verify.classify(phase, records, 0, False), "failure")
            records[2]["arg2"] = activity
            records[2]["arg0"] = 1
            self.assertEqual(verify.classify(phase, records, 0, False), "failure")
            records[2]["arg0"] = 52
            self.assertEqual(verify.classify(phase, records[:2] + records[3:], 0, False), "failure")
            records[1]["arg0"] = 1
            self.assertEqual(verify.classify(phase, records, 0, False), "failure")
            self.assertEqual(verify.classify(phase, records, 77, False), "failure")

    def test_timer_runs_both_phases_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "probe"
            binary.write_text("""#!%s
import json, os, sys
spin = 'spin' in sys.argv[1]
with open(os.path.join(os.environ['RUNNER_TEMP'], 'called'), 'a') as calls:
    calls.write(sys.argv[1] + '\\n')
rip, activity = (263, 0) if spin else (264, 1)
def fact(api, a, b, c):
    print(json.dumps(dict(api=api, edge='fact', result=0, arg0=a, arg1=b, arg2=c)), flush=True)
fact('guest_observation', 165, rip, 0)
fact('timer_guest_state', 52, rip, activity)
fact('sentinel_spin_verified' if spin else 'sentinel_hlt_timer_verified', 52, rip, 0)
fact('phase_result', 0, 1, 0)
fact('process_result', 0, 0, 1)
""" % sys.executable)
            binary.chmod(0o755)
            proc = subprocess.run([sys.executable, str(Path(__file__).with_name("verify-cr8-controls.py")), str(binary), "timer"], env=dict(os.environ, RUNNER_TEMP=tmp), capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual((Path(tmp) / "called").read_text().splitlines(), ["protected32-paging-spin-cr8-timer", "protected32-paging-hlt-cr8-timer"])

    def test_failed_spin_blocks_hlt(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "probe"
            called = Path(tmp) / "called"
            binary.write_text("#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$RUNNER_TEMP/called\"\nexit 1\n")
            binary.chmod(0o755)
            proc = subprocess.run([sys.executable, str(Path(__file__).with_name("verify-cr8-controls.py")), str(binary), "timer"], env=dict(os.environ, RUNNER_TEMP=tmp), capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(called.read_text().splitlines(), ["protected32-paging-spin-cr8-timer"])

    def test_timeout_never_retries(self):
        self.assertEqual(verify.classify("hlt", [], -9, True), "timeout")


if __name__ == "__main__":
    unittest.main()
