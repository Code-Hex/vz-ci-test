import importlib.util
import os
import sys
from pathlib import Path
import tempfile
import time
import unittest

scratch = tempfile.TemporaryDirectory()
os.environ["RUNNER_TEMP"] = scratch.name
spec = importlib.util.spec_from_file_location("capture", Path(__file__).with_name("verify-wait-capture.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def snapshot(seq=4, age=1, wait=None):
    return {"event": "pc_snapshot", "armed": True, "mach_write_bracket_valid": True,
            "out_of_range_cpu": 0, "wait_observer_error_seen": False,
            "cpus": [{"cpu": i, "coherent": True, "seq_before": seq, "seq_after": seq, "age_at_export_ns": age} for i in range(4)],
            "waits": [dict(cpu=i, coherent=True, trustworthy=True, counter_transport_valid=True,
                           invalid_count=0, error_seen=0, sequence_regressed=False,
                           seq_before=2, seq_after=2, captured=False) if not wait or i != wait["cpu"] else wait for i in range(4)]}


class Gate(unittest.TestCase):
    def setUp(self):
        capture.last_snapshot = None
        capture.last_received = 0
        capture.fresh_first = None
        capture.fresh_advanced = False
        capture.wait_positive = False

    def test_freshness_and_all_generations_advance(self):
        capture.observe(snapshot())
        self.assertTrue(capture.ready_snapshot())
        self.assertFalse(capture.fresh_advanced)
        partial = snapshot(6)
        partial["cpus"][3]["seq_before"] = 4
        partial["cpus"][3]["seq_after"] = 4
        capture.observe(partial)
        self.assertFalse(capture.fresh_advanced)
        capture.observe(snapshot(6))
        self.assertTrue(capture.fresh_advanced)
        capture.last_received = time.monotonic() - 2
        self.assertFalse(capture.ready_snapshot())
        capture.observe(snapshot(8, 250000000))
        self.assertFalse(capture.ready_snapshot())

    def test_other_cpu_invalid_after_positive_blocks_ready(self):
        wait = {"cpu": 1, "captured": True, "trustworthy": True, "coherent": True,
                "counter_transport_valid": True, "sequence_regressed": False,
                "invalid_count": 0, "error_seen": 0, "seq_before": 4, "seq_after": 4}
        capture.observe(snapshot(wait=wait))
        self.assertTrue(capture.wait_positive)
        self.assertTrue(capture.ready_snapshot())
        bad = snapshot(seq=6, wait=wait)
        bad["waits"][3]["invalid_count"] = 1
        capture.observe(bad)
        self.assertFalse(capture.ready_snapshot())
        self.assertTrue(capture.wait_positive)

    def test_wait_telemetry_has_joinable_bounded_lines(self):
        import json
        record = {
            "cpu": 0,
            "coherent": True,
            "trustworthy": True,
            "sequence_regressed": False,
            "seq_before": 2776,
            "seq_after": 2776,
            "counter_transport_valid": True,
            "invalid_count": 0,
            "error_seen": 0,
            "captured": True,
            "record_kind": 'latched_wait_sample',
            "current_profile_generation": 10516,
            "latest_profile_is_wait_sample": False,
            "age_at_export_ns": 2326625,
            "response_stable": True,
            "pending_before": 4,
            "pending_after": 4,
            "sample_timestamp_ns": 16842044703,
            "profile_generation": 10512,
            "pid": 32099,
            "tid": 85709,
            "rip": 18446743524055323074,
            "rbp": 18446743876329245712,
            "rbx": 18446743876329245792,
            "rsp": 18446743876329245664,
            "cs": 8,
            "rflags": 514,
            "frame": 18446743876329245440,
            "base": 18446743876329230336,
            "top": 18446743876329246720,
            "parent": 18446743876329245904,
            "return_pc": 18446743524055322177,
            "requested": 18446744073709551615,
            "called": 14,
            "parent_called": 14,
            "response_before": 10,
            "response_after": 10,
            "action": 18446743524060762240,
            "action_arg0": 18446743876329245920,
            "action_arg1": 0,
            "mode": 1,
            "slide": 97419264,
        }
        parts = capture.wait_events(record, {"snapshot": 1, "export_timestamp_ns": 16844371328,
                                            "mach_before_write_ns": 123456789012345, "mach_after_write_ns": 123456789012346})
        self.assertEqual(len(parts), 2)
        self.assertTrue(all(len(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode()) + 1 <= 900 for v in parts))
        self.assertEqual(parts[0]["event"], "wait_frame")
        self.assertEqual(parts[1]["event"], "wait_call")
        self.assertEqual(parts[0]["sample_timestamp_ns"], parts[1]["sample_timestamp_ns"])
        self.assertEqual(parts[0]["seq_before"], parts[1]["seq_before"])
        self.assertEqual(parts[0]["record"]["rip"], 18446743524055323074)
        self.assertEqual(parts[1]["record"]["pending_after"], 4)
        combined = dict(parts[0]["record"], **parts[1]["record"])
        self.assertEqual(combined, record)

    def test_timer_retry_is_bounded_and_failure_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_probes, old_out = capture.PROBES, capture.OUT
            capture.PROBES, capture.OUT = Path(tmp), Path(tmp)
            try:
                binary = Path(tmp) / "hypervisor"
                binary.write_text("""#!%s
import json, pathlib, sys, time
count = pathlib.Path('attempts')
count.write_text(count.read_text() + 'x' if count.exists() else 'x')
def fact(api, result, a, b, c):
    print(json.dumps(dict(api=api, edge='fact', result=result, arg0=a, arg1=b, arg2=c)), flush=True)
if pathlib.Path('slow').exists():
    time.sleep(3)
if pathlib.Path('ordinary_failure').exists():
    fact('process_result', 70, 70, 0, 0)
    sys.exit(70)
fact('guest_not_established', 77, 1, 256, 0)
fact('process_result', 77, 77, 0, 0)
sys.exit(77)
""" % sys.executable)
                binary.chmod(0o755)
                old_cwd = os.getcwd()
                os.chdir(tmp)
                try:
                    capture.observe(snapshot())
                    self.assertEqual(capture.run_timer("timer-spin", 5, retry_ready=lambda: True), "retry")
                    self.assertEqual((Path(tmp) / "attempts").read_text(), "xxx")
                    self.assertTrue(all((Path(tmp) / f"timer-spin-attempt{i}.jsonl").is_file() for i in range(1, 4)))
                    (Path(tmp) / "attempts").unlink()
                    self.assertEqual(capture.run_timer("timer-spin", 5, retry_ready=lambda: False), "failure")
                    self.assertEqual((Path(tmp) / "attempts").read_text(), "x")
                    (Path(tmp) / "attempts").unlink()
                    (Path(tmp) / "slow").touch()
                    self.assertEqual(capture.run_timer("timer-spin", 0.2, retry_ready=lambda: True), "timeout")
                    self.assertEqual((Path(tmp) / "attempts").read_text(), "x")
                    (Path(tmp) / "attempts").unlink()
                    (Path(tmp) / "slow").unlink()
                    (Path(tmp) / "ordinary_failure").touch()
                    self.assertEqual(capture.run_timer("timer-spin", 5, retry_ready=lambda: True), "failure")
                    self.assertEqual((Path(tmp) / "attempts").read_text(), "x")
                finally:
                    os.chdir(old_cwd)
            finally:
                capture.PROBES, capture.OUT = old_probes, old_out

    def test_linux_invocation_uses_binary_directory_and_requires_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "fixture"
            binary.write_text("#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$1\" \"$2\" PASS\n")
            binary.chmod(0o755)
            self.assertEqual(capture.run_linux(binary, 10), "success")
            raw = (capture.OUT / "linux.log").read_text().splitlines()
            self.assertEqual(Path(raw[0]).resolve(), binary.parent.resolve())
            self.assertEqual(raw[1:], ["-test.timeout=3m", "-test.v", "PASS"])
            binary.write_text("#!/bin/sh\necho 'not PASS'\n")
            self.assertEqual(capture.run_linux(binary, 10), "failure")

    def test_wait_positive_requires_trust_and_no_error(self):
        wait = {"cpu": 1, "captured": True, "trustworthy": True, "seq_before": 4,
                "invalid_count": 1, "error_seen": 0, "coherent": True, "counter_transport_valid": True,
                "sequence_regressed": False, "seq_after": 4}
        capture.observe(snapshot(wait=wait))
        self.assertFalse(capture.wait_positive)
        wait["invalid_count"] = 0
        wait["trustworthy"] = False
        capture.observe(snapshot(wait=wait))
        self.assertFalse(capture.wait_positive)
        wait["trustworthy"] = True
        capture.observe(snapshot(wait=wait))
        self.assertTrue(capture.wait_positive)


if __name__ == "__main__":
    unittest.main()
