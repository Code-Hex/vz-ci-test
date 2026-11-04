import importlib.util
import os
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
