import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("mtf", Path(__file__).with_name("verify-mtf-controls.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def fact(api, result=0, a=0, b=0, c=0):
    return {"api": api, "edge": "fact", "result": result, "arg0": a, "arg1": b, "arg2": c}


def snapshot():
    fields = {0x681e: 264, 0x681c: 4080, 0x6820: 2, 0x4826: 1, 0x4824: 0,
              0x4016: 0, 0x4000: 0x7f, 0x4002: (1 << 31) | (1 << 27) | (1 << 19) | (1 << 20),
              0x482e: 42, 0x400c: 0}
    facts = [fact("mtf_exit", 0, 37, 263, 0), fact("mtf_exit_tag", 0, 1, 165, 0),
             fact("mtf_exit", 0, 37, 264, 1), fact("mtf_exit_tag", 0, 2, 165, 0)]
    facts += [fact("mtf_guest_vmcs", 0, 2, key, value) for key, value in fields.items()]
    facts += [fact("mtf_guest_register", 0, 2, key, 0) for key in range(2, 18)]
    facts += [fact("mtf_snapshot_complete", 0, 2, 264, 1), fact("mtf_hlt_verified", 0, 37, 264, 1)]
    return facts


class Mtf(unittest.TestCase):
    def test_snapshot_preserves_guest_state_and_rejects_wrong_reason(self):
        facts = snapshot()
        state = r.valid_snapshot(facts)
        self.assertEqual(state["vmcs"][str(0x681e)], 264)
        self.assertEqual(len(state["registers"]), 16)
        self.assertFalse(state["timer_saved_on_exit"])
        facts[2]["arg0"] = 1
        with self.assertRaises(ValueError):
            r.valid_snapshot(facts)

    def test_snapshot_accepts_restored_pin_and_rejects_wrong_activity(self):
        facts = snapshot()
        pin = next(x for x in facts if x["api"] == "mtf_guest_vmcs" and x["arg1"] == 0x4000)
        pin["arg2"] = 0x3f
        self.assertEqual(r.valid_snapshot(facts)["vmcs"][str(0x4000)], 0x3f)
        facts[2]["arg2"] = 0
        with self.assertRaises(ValueError):
            r.valid_snapshot(facts)

    def test_snapshot_requires_all_guest_registers(self):
        facts = [x for x in snapshot() if not (x["api"] == "mtf_guest_register" and x["arg1"] == 7)]
        with self.assertRaises(ValueError):
            r.valid_snapshot(facts)

    def test_resume_requires_reason_rip_and_halted_activity(self):
        facts = [fact("mtf_resume_state_equal", 0, 264, 264, 1),
                 fact("mtf_resume_exit", 0, 52, 264, 1)]
        self.assertTrue(r.resume_verified(facts))
        facts[1]["arg2"] = 0
        self.assertFalse(r.resume_verified(facts))
        facts[1]["arg2"] = 1
        facts[1]["arg1"] = 265
        self.assertFalse(r.resume_verified(facts))

    def test_retry_only_clean_external_interrupt_before_checkpoint(self):
        facts = [fact("mtf_unexpected_exit", 77, 1, 1, 0), fact("process_result", 77, 77, 0, 0)]
        self.assertEqual(r.attempt_classification(facts, 77, False), "retry")
        self.assertEqual(r.attempt_classification(facts, 77, True), "timeout")
        facts[0]["arg0"] = 1 | (1 << 31)
        self.assertEqual(r.attempt_classification(facts, 77, False), "failure")
        facts[0]["arg0"] = 1
        facts.insert(1, fact("mtf_checkpoint_ready"))
        self.assertEqual(r.attempt_classification(facts, 77, False), "failure")


if __name__ == "__main__":
    unittest.main()
