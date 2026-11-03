#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import selectors
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name("hv-trace-summary.py")
spec = importlib.util.spec_from_file_location("hv_trace_summary", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
Tracker = module.Tracker

CPUID = """
343670028108                            0.0              1ac0009                              0                7ff7b691bd20     0                0                4275               2(AP) hypervisor(4064)
343671412192                         1384.1(1384.1)      1ac000a                              0                0                0                0                4275               2(AP) hypervisor(4064)
343671471281                           59.1              1ac0009                              4                7ff7b691bd18     0                0                4275               2(AP) hypervisor(4064)
343671472033                            0.8              1ac00a9                              0                1096c9000        0                1000             4275               2(AP) hypervisor(4064)
343671476669                            4.6(4.6)         1ac00aa                              0                7                0                0                4275               2(AP) hypervisor(4064)
343671476754                            0.1(5.5)         1ac000a                              4                0                0                0                4275               2(AP) hypervisor(4064)
343671483211                            6.5              1ac0009                              c                7ff7b691bd30     0                0                4275               2(AP) hypervisor(4064)
343671680408                          197.2(197.2)       1ac000a                              c                0                0                0                4275               2(AP) hypervisor(4064)
343671847286                          166.9              1ac000d                              c                1                0                0                4275               2(AP) hypervisor(4064)
343671847818                            0.5(0.5)         1ac000e                              c                0                0                0                4275               2(AP) hypervisor(4064)
343671881687                           33.9              1ac000d                              c                2                0                0                4275               2(AP) hypervisor(4064)
343671881831                            0.1(0.1)         1ac000e                              c                0                0                0                4275               2(AP) hypervisor(4064)
343671909948                           28.1              1ac000d                              c                3                0                0                4275               2(AP) hypervisor(4064)
343671910089                            0.1(0.1)         1ac000e                              c                0                0                0                4275               2(AP) hypervisor(4064)
343671940690                           30.6              1ac000d                              c                4                0                0                4275               2(AP) hypervisor(4064)
343671940956                            0.3(0.3)         1ac000e                              c                0                0                0                4275               2(AP) hypervisor(4064)
345778523262                      2106582.3              1ac000d                              1                508332b1ed       0                0                4275               0(AP) hypervisor(4064)
345778524869                            1.6              1ac0095                              0                508332b1ed       0                0                4275               0(AP) hypervisor(4064)
345778530836                            6.0              1ac0001                              0                0                0                0                4275               0(AP) hypervisor(4064)
345778683794                          153.0(153.0)       1ac0002                              0                30               0                0                4275               0(AP) hypervisor(4064)
345778698896                           15.1              1ac0055                              0                100              4                784              4275               0(AP) hypervisor(4064)
345778708178                            9.3(9.3)         1ac0056                              0                1                0                0                4275               0(AP) hypervisor(4064)
345778708428                            0.2              1ac0001                              0                0                0                0                4275               0(AP) hypervisor(4064)
345778872414                          164.0(164.0)       1ac0002                              0                a                0                0                4275               0(AP) hypervisor(4064)
345778891405                           19.0(366.5)       1ac0096                              0                0                0                0                4275               0(AP) hypervisor(4064)
345778891507                            0.1(368.2)       1ac000e                              1                0                0                0                4275               0(AP) hypervisor(4064)
347548725852                      1769834.3              1ac000d                              7                53               0                0                4275               2(AP) hypervisor(4064)
347548728255                            2.4              1ac008d                              0                4402             0                0                4275               2(AP) hypervisor(4064)
347548728428                            0.2              1ac008c                              0                a                0                0                4275               2(AP) hypervisor(4064)
347548728485                            0.1(2.6)         1ac000e                              7                0                0                0                4275               2(AP) hypervisor(4064)
347548738576                           10.1              1ac000d                              7                4c               0                0                4275               2(AP) hypervisor(4064)
347548738724                            0.1              1ac008d                              0                681e             0                0                4275               2(AP) hypervisor(4064)
347548738884                            0.2              1ac008c                              0                105              0                0                4275               2(AP) hypervisor(4064)
347548738934                            0.1(0.4)         1ac000e                              7                0                0                0                4275               2(AP) hypervisor(4064)
347548745824                            6.9              1ac000d                              7                58               0                0                4275               2(AP) hypervisor(4064)
347548745862                            0.0              1ac008d                              0                440c             0                0                4275               2(AP) hypervisor(4064)
347548745926                            0.1              1ac008c                              0                2                0                0                4275               2(AP) hypervisor(4064)
347548745973                            0.0(0.1)         1ac000e                              7                0                0                0                4275               2(AP) hypervisor(4064)
349601103781                      2052357.8              1ac000d                              5                120a8            0                0                4275               2(AP) hypervisor(4064)
349601311807                          208.0(208.0)       1ac000e                              5                0                0                0                4275               2(AP) hypervisor(4064)
349601322135                           10.3              1ac0009                              5                7ff7b691bd10     0                0                4275               2(AP) hypervisor(4064)
349601322810                            0.7              1ac00b1                              0                0                1000             0                4275               2(AP) hypervisor(4064)
349601576580                          253.8(253.8)       1ac00b2                              0                0                0                0                4275               2(AP) hypervisor(4064)
349601576851                            0.3(254.7)       1ac000a                              5                0                0                0                4275               2(AP) hypervisor(4064)
349601588434                           11.6              1ac0009                              1                120a8            0                0                4275               2(AP) hypervisor(4064)
349602534423                          946.0(946.0)       1ac000a                              1                0                0                0                4275               2(AP) hypervisor(4064)
"""

HLT_PREFIX = """
614496444470                            0.0              1ac0009                              0                7ff7b6021d20     0                0                6dbf               0(AP) hypervisor(8178)
614496953259                          508.8(508.8)       1ac000a                              0                0                0                0                6dbf               0(AP) hypervisor(8178)
614496980628                           27.4              1ac0009                              4                7ff7b6021d18     0                0                6dbf               0(AP) hypervisor(8178)
614496981489                            0.9              1ac00a9                              0                109fc3000        0                1000             6dbf               0(AP) hypervisor(8178)
614496985946                            4.5(4.5)         1ac00aa                              0                7                0                0                6dbf               0(AP) hypervisor(8178)
614496986037                            0.1(5.4)         1ac000a                              4                0                0                0                6dbf               0(AP) hypervisor(8178)
614496992039                            6.0              1ac0009                              c                7ff7b6021d30     0                0                6dbf               0(AP) hypervisor(8178)
614497112709                          120.7(120.7)       1ac000a                              c                0                0                0                6dbf               0(AP) hypervisor(8178)
614497198428                           85.7              1ac000d                              c                1                0                0                6dbf               0(AP) hypervisor(8178)
614497198974                            0.5(0.5)         1ac000e                              c                0                0                0                6dbf               0(AP) hypervisor(8178)
614497224552                           25.6              1ac000d                              c                2                0                0                6dbf               0(AP) hypervisor(8178)
614497224628                            0.1(0.1)         1ac000e                              c                0                0                0                6dbf               0(AP) hypervisor(8178)
614497267529                           42.9              1ac000d                              c                3                0                0                6dbf               0(AP) hypervisor(8178)
614497268040                            0.5(0.5)         1ac000e                              c                0                0                0                6dbf               0(AP) hypervisor(8178)
614497287815                           19.8              1ac000d                              c                4                0                0                6dbf               0(AP) hypervisor(8178)
614497287932                            0.1(0.1)         1ac000e                              c                0                0                0                6dbf               0(AP) hypervisor(8178)
616602584801                      2105296.9              1ac000d                              1                8f9191ef70       0                0                6dbf               2(AP) hypervisor(8178)
616602585852                            1.1              1ac0095                              0                8f9191ef70       0                0                6dbf               2(AP) hypervisor(8178)
616602589322                            3.5              1ac0001                              0                0                0                0                6dbf               2(AP) hypervisor(8178)
616602731634                          142.3(142.3)       1ac0002                              0                30               0                0                6dbf               2(AP) hypervisor(8178)
616602763332                           31.7              1ac0055                              0                100              4                784              6dbf               2(AP) hypervisor(8178)
616602772256                            8.9(8.9)         1ac0056                              0                1                0                0                6dbf               2(AP) hypervisor(8178)
616602772400                            0.1              1ac0001                              0                0                0                0                6dbf               2(AP) hypervisor(8178)
"""

def event(timestamp=1, code="1ac0001", pid=10, tid="a", process="hypervisor"):
    return f"{timestamp} 0.1(0.1) {code} 0 0 0 0 {tid} 2(AP) {process}({pid})"


class TrackerTests(unittest.TestCase):
    def track(self, text, **options):
        tracker = Tracker(**options)
        for line in text.splitlines():
            tracker.feed(line)
        return tracker.snapshot()

    def test_cpuid_fixture_is_balanced_for_tracked_families(self):
        result = self.track(CPUID)
        self.assertEqual(result["counts"]["events"], 46)
        self.assertEqual(result["counts"]["tracked"], 34)
        self.assertEqual(result["counts"]["balanced"], 17)
        self.assertEqual(result["counts"]["orphan"], 0)
        self.assertEqual(result["counts"]["overwritten"], 0)
        self.assertEqual(result["pendingCount"], 0)
        self.assertEqual(result["observedFamilies"], {
            "0x1ac0008": 10, "0x1ac00a8": 2, "0x1ac000c": 18,
            "0x1ac0094": 2, "0x1ac0000": 4, "0x1ac0054": 2,
            "0x1ac008c": 6, "0x1ac00b0": 2,
        })
        self.assertEqual(result["families"]["task_trap"]["balanced"], 5)
        self.assertEqual(result["families"]["thread_trap"]["balanced"], 9)
        self.assertEqual(result["families"]["run_until"]["balanced"], 1)
        self.assertEqual(result["families"]["enter"]["balanced"], 2)

    def test_hlt_fixture_retains_three_pending_begins(self):
        result = self.track(HLT_PREFIX)
        self.assertEqual(result["counts"]["events"], 23)
        self.assertEqual(result["counts"]["balanced"], 8)
        self.assertEqual(result["pendingCount"], 3)
        self.assertEqual([(p["pid"], p["tid"], p["family"], p["timestamp"])
                          for p in result["pending"]], [
            (8178, "6dbf", "enter", 616602772400),
            (8178, "6dbf", "run_until", 616602585852),
            (8178, "6dbf", "thread_trap", 616602584801),
        ])
        self.assertIn("1ac0001", result["pending"][0]["raw"])

    def test_pid_tid_and_family_are_independent(self):
        result = self.track("\n".join([
            event(1, pid=1, tid="a"), event(2, pid=2, tid="a"),
            event(3, pid=1, tid="b"), event(4, "1ac0002", pid=1, tid="a"),
        ]))
        self.assertEqual(result["counts"]["balanced"], 1)
        self.assertEqual([(p["pid"], p["tid"]) for p in result["pending"]], [(1, "b"), (2, "a")])

    def test_orphan_unknown_malformed_and_overwrite_are_distinct(self):
        result = self.track("\n".join([
            "abstime delta(us)(duration) debug-id arg1 arg2 arg3 arg4 thread-id cpu process-name(pid)",
            "not a trace", event(1, "1ac0002"), event(2, "1ac0ff1"),
            event(3), event(4), event(5, "1ac0002"),
        ]))
        self.assertEqual(result["counts"]["malformed"], 1)
        self.assertEqual(result["counts"]["orphan"], 1)
        self.assertEqual(result["counts"]["untracked"], 1)
        self.assertEqual(result["counts"]["overwritten"], 1)
        self.assertEqual(result["counts"]["balanced"], 1)
        self.assertEqual(result["pendingCount"], 0)

    def test_loss_indicators_are_recorded_without_guessing_lost_count(self):
        result = self.track("\n".join(["ktrace: lost 100 events", event(1, "7020008", pid=0)]))
        self.assertEqual(result["counts"]["traceLostIndicators"], 2)
        self.assertEqual(result["counts"]["malformed"], 0)

    def test_pending_storage_and_output_are_bounded(self):
        tracker = Tracker(max_pending=3)
        for pid in range(10):
            tracker.feed(event(pid+1, pid=pid))
        result = tracker.snapshot()
        self.assertEqual(result["pendingCount"], 3)
        self.assertEqual(result["counts"]["pendingDropped"], 7)
        self.assertEqual([p["pid"] for p in result["pending"]], [9, 8, 7])
        tracker = Tracker()
        for pid in range(100):
            tracker.feed(event(pid+1, pid=pid, process="quoted\"☃"*300))
        encoded = module.encode_snapshot(tracker.snapshot())
        self.assertLessEqual(len(encoded.encode("utf-8")), 8192)
        packet = json.loads(encoded)
        self.assertLessEqual(len(packet["pending"]), 16)
        self.assertEqual(packet["pendingCount"], 100)
        self.assertGreater(packet["counts"]["rawTruncated"], 0)

    def test_completed_actors_leave_no_pending_history(self):
        tracker = Tracker(max_pending=3)
        for pid in range(100):
            tracker.feed(event(2*pid+1, pid=pid))
            tracker.feed(event(2*pid+2, "1ac0002", pid=pid))
        result = tracker.snapshot()
        self.assertEqual(result["counts"]["balanced"], 100)
        self.assertEqual(result["pendingCount"], 0)
        self.assertEqual(result["counts"]["pendingDropped"], 0)

    def test_cli_emits_only_final_json_on_immediate_eof(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], input=event()+"\n", text=True,
                                capture_output=True, timeout=3, check=True)
        packets = result.stdout.splitlines()
        self.assertEqual(len(packets), 1)
        self.assertEqual(result.stderr, "")
        final = json.loads(packets[0])
        self.assertTrue(final["final"])
        self.assertEqual(final["stopReason"], "eof")
        self.assertEqual(final["pendingCount"], 1)

    def test_cli_emits_periodic_snapshot_while_input_remains_open(self):
        with subprocess.Popen([sys.executable, str(SCRIPT)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            try:
                process.stdin.write(event()+"\n")
                process.stdin.flush()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(3), "periodic summary was not emitted")
                periodic = json.loads(process.stdout.readline())
                self.assertFalse(periodic["final"])
                self.assertEqual(periodic["pendingCount"], 1)
                self.assertGreaterEqual(periodic["collectorElapsed"], 0.9)
                process.stdin.close()
                process.wait(timeout=3)
                remaining = [json.loads(line) for line in process.stdout]
                self.assertTrue(remaining[-1]["final"])
                self.assertEqual(remaining[-1]["pendingCount"], 1)
                self.assertEqual(process.stderr.read(), "")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    unittest.main()
