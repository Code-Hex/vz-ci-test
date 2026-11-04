import importlib.util
import os
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("boundary", Path(__file__).with_name("verify-mtf-signal-boundary.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class Boundary(unittest.TestCase):
    def test_release_deadline_is_strict(self):
        self.assertTrue(b.release_allowed(44.999, 45.0))
        self.assertFalse(b.release_allowed(45.0, 45.0))
        self.assertFalse(b.release_allowed(45.001, 45.0))

    def test_ready_line_framing_keeps_following_lines(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"ready":true}\n{"later":1}\n')
            line, pending = b.read_ready_line(read_fd, 1)
            self.assertEqual(line, b'{"ready":true}')
            self.assertEqual(pending, b'{"later":1}\n')
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_signal_only_after_all_durable_milestones(self):
        steps = []
        result = b.decide_termination(["stage2", "30", "60", "90"], False, lambda: steps.append("ack") or True,
                                      lambda: steps.append("signal"))
        self.assertEqual(result, "signalled")
        self.assertEqual(steps, ["ack", "signal"])

    def test_failed_ack_or_missing_milestone_does_not_signal(self):
        calls = []
        result = b.decide_termination(["stage2", "30", "60", "90"], False, lambda: False,
                                      lambda: calls.append("signal"))
        self.assertEqual(result, "inconclusive")
        self.assertEqual(calls, [])
        self.assertEqual(b.decide_termination(["stage2", "30"], False, lambda: True,
                                               lambda: calls.append("signal")), "inconclusive")
        self.assertEqual(calls, [])

    def test_stage2_requires_duration_phase_pid_and_source(self):
        identity = {"owner_pid": 17, "source_sha256": "a" * 64}
        record = {"api": "mtf_run_until", "edge": "before", "phase": "mtf-hlt-observe",
                  "pid": 17, "sourcehash": "a" * 64, "arg1": 2, "arg2": 20000000}
        self.assertTrue(b.valid_stage2(record, identity))
        for key, value in (("arg2", 0), ("phase", "other"), ("pid", 18), ("sourcehash", "b" * 64)):
            bad = dict(record, **{key: value})
            self.assertFalse(b.valid_stage2(bad, identity))

    def test_early_return_requires_full_cleanup_and_both_gates(self):
        result = {"api": "process_result", "edge": "fact", "result": 0, "arg0": 0, "arg1": 0, "arg2": 1}
        stage2 = {"api": "mtf_run_until", "edge": "return", "phase": "mtf-hlt-observe", "arg1": 2, "result": 0}
        self.assertEqual(b.early_completion([stage2, result], {"mov": 1, "hlt": 2}, 0, True), "returned_clean")
        self.assertEqual(b.early_completion([result], {"mov": 1}, 0, True), "inconclusive_cleanup")
        self.assertEqual(b.early_completion([result], {"mov": 1, "hlt": 2}, None, False), "inconclusive_cleanup")

    def test_milestone_drains_before_and_after_request(self):
        calls, state = [], {"returned": False}
        def drain():
            calls.append("drain")
        def publish(payload):
            calls.append(payload["return_observed_before_request"])
            state["returned"] = True
        self.assertTrue(b.observe_and_publish(state, drain, publish))
        self.assertEqual(calls, ["drain", False, "drain"])
        self.assertFalse(b.observe_and_publish(state, drain, publish))

    def test_early_return_never_signals(self):
        calls = []
        self.assertEqual(b.decide_termination(["stage2", "30", "60", "90"], True,
                                               lambda: calls.append("ack"),
                                               lambda: calls.append("signal")), "returned")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
