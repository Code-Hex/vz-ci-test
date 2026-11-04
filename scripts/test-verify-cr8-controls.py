import importlib.util
from pathlib import Path
import unittest

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

    def test_timeout_never_retries(self):
        self.assertEqual(verify.classify("hlt", [], -9, True), "timeout")


if __name__ == "__main__":
    unittest.main()
