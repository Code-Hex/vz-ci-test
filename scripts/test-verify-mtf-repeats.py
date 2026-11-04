import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("repeats", Path(__file__).with_name("verify-mtf-repeats.py"))
repeats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repeats)


class Repeats(unittest.TestCase):
    def run_case(self, outcomes):
        calls, rounds = [], []
        def run(round_number, attempt):
            calls.append((round_number, attempt))
            return next(outcomes)
        result = repeats.run_rounds(run, rounds.append)
        return result, calls, rounds

    def test_ten_successful_fresh_rounds(self):
        result, calls, rounds = self.run_case(iter(["success"] * 10))
        self.assertTrue(result)
        self.assertEqual(calls, [(i, 1) for i in range(1, 11)])
        self.assertEqual([r["round"] for r in rounds], list(range(1, 11)))

    def test_only_clean_interrupt_retries_and_failure_stops(self):
        result, calls, rounds = self.run_case(iter(["retry", "success", "timeout"]))
        self.assertFalse(result)
        self.assertEqual(calls, [(1, 1), (1, 2), (2, 1)])
        self.assertEqual(rounds[0]["attempts"], ["retry", "success"])
        self.assertEqual(rounds[1]["result"], "timeout")

    def test_interrupt_retries_bounded(self):
        result, calls, rounds = self.run_case(iter(["retry"] * 3))
        self.assertFalse(result)
        self.assertEqual(calls, [(1, 1), (1, 2), (1, 3)])
        self.assertEqual(rounds[0]["result"], "retry_exhausted")


if __name__ == "__main__":
    unittest.main()
