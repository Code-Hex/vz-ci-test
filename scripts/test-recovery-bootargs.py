import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bootargs", Path(__file__).with_name("recovery_bootargs.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
MARKER = {"baseline": "old", "nonce": "b" * 64, "binding": "123/1/" + "a" * 40}
CANARY = "vz-ci-persistence-probe"


class Platform:
    def __init__(self, value):
        self.value, self.events, self.fail_write = value, [], False
        self.active_value = b"preempt=10"

    def read(self):
        return self.value

    def write(self, path, owned_canary, expected_previous):
        self.events.append("write")
        self.value = b.parse_nvram(path.read_bytes())
        if self.fail_write:
            self.fail_write = False
            raise OSError("write response lost")

    def active(self):
        self.events.append("active")
        if isinstance(self.active_value, Exception):
            raise self.active_value
        return self.active_value

    def inventory(self):
        self.events.append("inventory")
        return {"debugger_count": None, "virtio_network_classes": [], "nic_inventory_status": "unsupported"}


class BootArgumentProfile(unittest.TestCase):
    def test_canonical_spacing_and_exact_token_sequence(self):
        expected = {'status': 'observed', 'debug_mask': 8192, 'nondebug_token_count': 3,
                    'nondebug_sha256': '11a6f7c443706e6d2af0396c32aa8d5350a93892d43185cdacfe1430b82d9505'}
        self.assertEqual(b.boot_argument_profile(' alpha=1  beta\talpha=1  --debug=0x2000 '), expected)
        self.assertEqual(b.boot_argument_profile(b'alpha=1\tbeta alpha=1 -debug=8192'), expected)
        self.assertNotEqual(b.boot_argument_profile('beta alpha=1 alpha=1')['nondebug_sha256'], expected['nondebug_sha256'])
        self.assertNotEqual(b.boot_argument_profile('alpha=1 beta')['nondebug_sha256'], expected['nondebug_sha256'])

    def test_only_exact_debug_key_is_excluded(self):
        result = b.boot_argument_profile('debugger=1 xdebug=3 -debugger=2 debug=0')
        self.assertEqual(result['debug_mask'], 0)
        self.assertEqual(result['nondebug_token_count'], 3)
        self.assertEqual(result['nondebug_sha256'], b.boot_argument_profile('debugger=1 xdebug=3 -debugger=2')['nondebug_sha256'])
        self.assertNotIn('debugger', json.dumps(result))

    def test_empty_and_debug_only_have_same_nondebug_hash(self):
        empty = b.boot_argument_profile('')
        debug = b.boot_argument_profile('--debug=0x2000')
        self.assertEqual(empty['nondebug_sha256'], '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945')
        self.assertEqual((empty['nondebug_token_count'], debug['nondebug_token_count']), (0, 0))
        self.assertEqual(empty['nondebug_sha256'], debug['nondebug_sha256'])
        self.assertIsNone(empty['debug_mask'])

    def test_invalid_values_propagate(self):
        for value in ('debug=1 debug=2', 'debug=wat', 'debug', '_router_ip=1', b'x\n', 'x' * 1024, None, 'é'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                b.boot_argument_profile(value)


class Bootargs(unittest.TestCase):
    def save(self, path, data):
        with path.open("xb") as stream:
            stream.write(data)

    def test_two_key_combinations_are_observed_before_restore(self):
        for boot_staged in (False, True):
            for canary_staged in (False, True):
                with self.subTest(boot_staged=boot_staged, canary_staged=canary_staged), tempfile.TemporaryDirectory() as tmp:
                    directory, original = Path(tmp), {"boot-args": b"preempt=10"}
                    platform = Platform(original.copy())
                    b.stage(directory, MARKER, platform, self.save, lambda _p: None)
                    staged = platform.value.copy()
                    self.assertEqual(staged[CANARY], b"v1:123:1:" + b"b" * 64)
                    platform.value = {"boot-args": staged["boot-args"] if boot_staged else original["boot-args"]}
                    if canary_staged:
                        platform.value[CANARY] = staged[CANARY]
                    expected = {"boot_args": "staged" if boot_staged else "original",
                                "canary": "staged" if canary_staged else "original"}
                    def save(path, data):
                        self.save(path, data)
                        if path.name == "debug-boot-observed.json":
                            self.assertEqual(json.loads(data)["nvram_key_states"], expected)
                            self.assertEqual(CANARY in platform.value, canary_staged)
                    facts = b.finish(directory, MARKER, platform, save, lambda _p: None, current_boot_uuid="new", inventory=False)
                    self.assertEqual(facts["nvram_key_states"], expected)
                    self.assertEqual(facts["nvram_before_restore"], "staged" if all(expected[k] == "staged" for k in expected) else
                                     "original" if all(expected[k] == "original" for k in expected) else "partial")
                    self.assertEqual(platform.value, original)
                    self.assertNotIn(staged[CANARY].decode(), json.dumps(facts))
                    again = b.finish(directory, MARKER, platform, save, lambda _p: None, current_boot_uuid="new", inventory=False)
                    self.assertEqual(again["nvram_key_states"], expected)

    def test_existing_canary_and_foreign_values_never_mutate(self):
        for value in (b"", b"foreign", "foreign", 1):
            with self.subTest(existing=value), tempfile.TemporaryDirectory() as tmp:
                platform = Platform({CANARY: value})
                with self.assertRaises(ValueError):
                    b.stage(Path(tmp), MARKER, platform, self.save, lambda _p: None)
                self.assertNotIn("write", platform.events)
        for foreign in ({CANARY: b"other-nonce"}, {"boot-args": b"foreign=1"},
                        {CANARY: b.canary_value(MARKER).decode()}, {"boot-args": "preempt=10 debug=0x2000"}):
            with self.subTest(foreign=foreign), tempfile.TemporaryDirectory() as tmp:
                directory, platform = Path(tmp), Platform({"boot-args": b"preempt=10"})
                b.stage(directory, MARKER, platform, self.save, lambda _p: None)
                platform.value.update(foreign)
                before = platform.value.copy()
                platform.events.clear()
                staged = b.desired({"boot-args": b"preempt=10"}, MARKER)
                _whole, states = b.key_states({"boot-args": b"preempt=10"}, staged, before)
                self.assertIn("other", states.values())
                facts = b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertFalse(facts["nvram_restored"])
                self.assertEqual(facts["nvram_before_restore"], "other")
                self.assertEqual(facts["nvram_key_states"], states)
                self.assertEqual(json.loads((directory / "debug-boot-observed.json").read_text())["nvram_key_states"], states)
                self.assertEqual(platform.value, before)
                self.assertNotIn("write", platform.events)
                platform.value.update({"boot-args": "another foreign type", CANARY: b"another foreign nonce"})
                again = b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertFalse(again["nvram_restored"])
                self.assertEqual(again["nvram_key_states"], states)
                self.assertNotIn("write", platform.events)
                for marker in (dict(MARKER, nonce="c" * 64), dict(MARKER, binding="124/1/" + "a" * 40)):
                    with self.assertRaises(ValueError):
                        b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertNotIn("write", platform.events)
        with self.assertRaises(ValueError):
            b.parse_nvram(plistlib.dumps({"other:" + CANARY: b"foreign"}))

    def test_canary_payload_requires_bound_marker(self):
        for marker in (dict(MARKER, nonce="invalid"), dict(MARKER, binding="foreign")):
            with self.assertRaises(ValueError):
                b.canary_value(marker)

    def test_canary_removal_failure_and_silent_failure_retry(self):
        for failure in ("error", "silent"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                directory, state = Path(tmp), {"boot-args": b"preempt=10"}
                events, fail_delete = [], [True]
                def capture(argv, *_args):
                    if argv == ["/usr/sbin/nvram", "-x", "-p"]:
                        return plistlib.dumps(state)
                    if argv[0] == "/usr/sbin/sysctl":
                        return b"preempt=10\n"
                    if argv[1:3] == ["-x", "-f"]:
                        state.update(b.parse_nvram(Path(argv[3]).read_bytes()))
                        return b""
                    if argv[1] == "-d":
                        self.assertEqual(argv[2], CANARY)
                        events.append("delete")
                        if fail_delete[0]:
                            fail_delete[0] = False
                            if failure == "error":
                                raise OSError("delete response failed")
                        else:
                            state.pop(CANARY)
                        return b""
                    self.assertEqual(argv, ["/usr/sbin/nvram", "-s"])
                    events.append("sync")
                    return b""
                with patch.object(b, "capture", capture):
                    platform = b.MacPlatform()
                    b.stage(directory, MARKER, platform, self.save, lambda _p: None)
                    with self.assertRaises((OSError, ValueError)):
                        b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                    self.assertFalse((directory / "debug-boot-restored.json").exists())
                    self.assertIn(CANARY, state)
                    facts = b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertTrue(facts["nvram_restored"])
                self.assertEqual(facts["nvram_key_states"], {"boot_args": "staged", "canary": "staged"})
                self.assertEqual(state, {"boot-args": b"preempt=10"})
                self.assertEqual(events.count("delete"), 2)
                self.assertEqual(events[-2:], ["delete", "sync"])

    def test_writer_refuses_foreign_canary_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "original.plist"
            path.write_bytes(plistlib.dumps({"boot-args": b"preempt=10"}))
            calls = []
            def capture(argv, *_args):
                calls.append(argv)
                return plistlib.dumps({CANARY: b"foreign"})
            with patch.object(b, "capture", capture):
                with self.assertRaises(ValueError):
                    b.MacPlatform().write(path, b.canary_value(MARKER), {"boot-args": b"preempt=10", CANARY: b.canary_value(MARKER)})
            self.assertEqual(calls, [["/usr/sbin/nvram", "-x", "-p"]])

    def test_writer_does_not_ignore_changed_bootargs_on_second_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, platform = Path(tmp), Platform({"boot-args": b"preempt=10"})
            b.stage(directory, MARKER, platform, self.save, lambda _p: None)
            staged, calls, reads = platform.value.copy(), [], []
            def capture(argv, *_args):
                calls.append(argv)
                if argv[0] == "/usr/sbin/sysctl":
                    return b"preempt=10\n"
                self.assertEqual(argv, ["/usr/sbin/nvram", "-x", "-p"])
                reads.append("read")
                return plistlib.dumps(staged if len(reads) == 1 else {**staged, "boot-args": b"external=1"})
            with patch.object(b, "capture", capture):
                facts = b.finish(directory, MARKER, b.MacPlatform(), self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
            self.assertFalse(facts["nvram_restored"])
            self.assertEqual(facts["nvram_key_states"], {"boot_args": "staged", "canary": "staged"})
            self.assertFalse((directory / "debug-boot-restored.json").exists())
            self.assertEqual(len(calls), 3)

    def test_platform_write_and_delete_request_force_sync_after_mutation(self):
        for value in ({"boot-args": b"preempt=10"}, {}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "value.plist"
                path.write_bytes(plistlib.dumps(value))
                calls = []
                def capture(argv):
                    calls.append(argv)
                    return plistlib.dumps({"boot-args": b"preempt=10", CANARY: b.canary_value(MARKER)})
                with patch.object(b, "capture", capture):
                    b.MacPlatform().write(path, b.canary_value(MARKER), {"boot-args": b"preempt=10", CANARY: b.canary_value(MARKER)})
                mutations = [["/usr/sbin/nvram", "-x", "-f", str(path)]] if value else [["/usr/sbin/nvram", "-d", "boot-args"]]
                self.assertEqual(calls, [["/usr/sbin/nvram", "-x", "-p"], *mutations,
                                        ["/usr/sbin/nvram", "-d", CANARY], ["/usr/sbin/nvram", "-s"]])

    def test_failed_force_sync_prevents_restore_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            state, syncs = {"boot-args": b"preempt=10"}, []
            def capture(argv, *_args):
                if argv == ["/usr/sbin/nvram", "-x", "-p"]:
                    return plistlib.dumps(state)
                if argv[0] == "/usr/sbin/sysctl":
                    return b"preempt=10\n"
                if argv[1:3] == ["-x", "-f"]:
                    state.update(b.parse_nvram(Path(argv[3]).read_bytes()))
                    return b""
                if argv[1] == "-d":
                    state.pop(argv[2], None)
                    return b""
                self.assertEqual(argv, ["/usr/sbin/nvram", "-s"])
                syncs.append("sync")
                if len(syncs) == 2:
                    raise OSError("sync request failed")
                return b""
            with patch.object(b, "capture", capture):
                platform = b.MacPlatform()
                b.stage(directory, marker, platform, self.save, lambda _p: None)
                with self.assertRaises(OSError):
                    b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertFalse((directory / "debug-boot-restored.json").exists())
                self.assertEqual(syncs, ["sync", "sync"])
                def save(path, data):
                    if path.name == "debug-boot-restored.json":
                        self.assertEqual(syncs, ["sync", "sync", "sync"])
                    self.save(path, data)
                facts = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new", inventory=False)
            self.assertTrue(facts["nvram_restored"])
            self.assertTrue((directory / "debug-boot-restored.json").exists())

    def test_input_and_type_preservation(self):
        for original in ({}, {"boot-args": "preempt=10"}, {"boot-args": b"preempt=10"}, {"boot-args": b""}):
            staged = b.desired(original, MARKER)
            self.assertEqual(b.debug_mask(staged["boot-args"]), 0x2000)
            if original:
                self.assertIs(type(staged["boot-args"]), type(original["boot-args"]))
        for raw in (b"", b"garbage", plistlib.dumps([]), plistlib.dumps({"boot-args": 1}),
                    plistlib.dumps({"other:boot-args": b""})):
            with self.assertRaises(ValueError):
                b.parse_nvram(raw)
        for value in ("debug=0", "_panicd_ip=1.1.1.1", "_router_ip=1.1.1.1", "_panicd_corename=x"):
            with self.assertRaises(ValueError):
                b.desired({"boot-args": value}, MARKER)

    def test_stage_saved_before_write_and_restore_before_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            original = {"boot-args": b"preempt=10"}
            platform = Platform(original)
            marker = dict(MARKER)
            def save(path, data):
                self.save(path, data)
                platform.events.append(path.name)
            b.stage(directory, marker, platform, save, lambda _p: platform.events.append("sync"))
            self.assertLess(platform.events.index("debug-boot-stage.json"), platform.events.index("write"))
            self.assertLess(platform.events.index("sync"), platform.events.index("write"))
            platform.events.clear()
            platform.active_value = b"preempt=10 debug=0x2000"
            facts = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(platform.value, original)
            self.assertEqual(facts["active_debug_mask"], 0x2000)
            self.assertTrue(facts["nvram_restored"])
            self.assertLess(platform.events.index("write"), platform.events.index("inventory"))
            self.assertEqual(facts["nic_inventory_status"], "unsupported")
            with self.assertRaises(FileExistsError):
                b.stage(directory, marker, platform, save, lambda _p: None)

    def test_write_failure_restores_and_absent_restores_to_absent(self):
        for original in ({}, {"boot-args": ""}):
            with self.subTest(original=original), tempfile.TemporaryDirectory() as tmp:
                directory, platform = Path(tmp), Platform(original)
                platform.fail_write = True
                with self.assertRaises(OSError):
                    b.stage(directory, dict(MARKER), platform, self.save, lambda _p: None)
                self.assertEqual(platform.value, original)
                self.assertTrue(json.loads((directory / "debug-boot-restored.json").read_text())["nvram_restored"])

    def test_invalid_active_mask_still_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.active_value = b"debug=invalid"
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertIsNone(facts["active_debug_mask"])
            self.assertTrue(facts["nvram_restored"])
            self.assertEqual(platform.value, original)

    def test_identity_or_unexpected_nvram_prevents_overwrite_and_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({"boot-args": "preempt=10"})
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.value = {"boot-args": "other=1"}
            platform.events.clear()
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertFalse(facts["nvram_restored"])
            self.assertEqual(facts["nvram_key_states"]["boot_args"], "other")
            with self.assertRaises(ValueError):
                b.finish(directory, dict(MARKER, baseline="other"), platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertNotIn("write", platform.events)
            self.assertNotIn("inventory", platform.events)

    def test_capture_rejects_oversized_child_output(self):
        with self.assertRaises(ValueError):
            b.capture([sys.executable, "-c", "print('oversized')"], limit=2)

    def test_unstaged_rollback_only_accepts_clean_nvram(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({"boot-args": "preempt=10"})
            b.rollback(directory, marker, platform, self.save, lambda _p: None)
            self.assertNotIn("write", platform.events)
            platform.value = {"boot-args": "debug=0x2000"}
            with self.assertRaises(ValueError):
                b.rollback(directory, marker, platform, self.save, lambda _p: None)
            original = directory / "debug-boot-original.plist"
            self.save(original, plistlib.dumps({"boot-args": "preempt=10"}))
            with self.assertRaises(ValueError):
                b.rollback(directory, marker, platform, self.save, lambda _p: None)
            original.write_bytes(b"")
            with self.assertRaises(ValueError):
                b.rollback(directory, marker, platform, self.save, lambda _p: None)
            self.assertNotIn("write", platform.events)

    def test_active_status_and_nvram_before_restore_are_distinct(self):
        for value, status, mask in ((b"preempt=10", "observed_no_debug", None),
                                    (b"debug=0x2000", "observed_debug", 0x2000),
                                    (OSError("unavailable"), "unavailable", None),
                                    (b"debug=invalid", "invalid", None)):
            for before in ("staged", "original"):
                with self.subTest(status=status, before=before), tempfile.TemporaryDirectory() as tmp:
                    directory, original = Path(tmp), {"boot-args": b"preempt=10"}
                    platform, marker = Platform(original), dict(MARKER)
                    b.stage(directory, marker, platform, self.save, lambda _p: None)
                    if before == "original":
                        platform.value = original
                    platform.active_value = value
                    platform.events.clear()
                    def save(path, data):
                        self.save(path, data)
                        platform.events.append(path.name)
                    facts = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
                    self.assertEqual(facts["active_bootargs_status"], status)
                    self.assertEqual(facts["active_debug_mask"], mask)
                    self.assertEqual(facts["nvram_before_restore"], before)
                    self.assertFalse(facts["restored_marker_preexisting"])
                    if before == "staged":
                        self.assertLess(platform.events.index("debug-boot-observed.json"), platform.events.index("write"))
                    again = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
                    self.assertEqual(again["nvram_before_restore"], before)
                    self.assertFalse(again["restored_marker_preexisting"])

    def test_preexisting_restore_receipt_identifies_oldboot_writer_without_raw_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            self.assertEqual(b.rollback(directory, marker, platform, self.save, lambda _p: None), "staged")
            receipt = directory / "debug-boot-restored.json"
            data = json.loads(receipt.read_text())
            data["raw"] = "not published"
            receipt.write_text(json.dumps(data))
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertTrue(facts["restored_marker_preexisting"])
            self.assertEqual(facts["restore_receipt"], {"status": "observed", "cause": "preintent_abort",
                                                     "actual_boot_uuid": "old", "nvram_before_restore": "staged",
                                                     "nvram_key_states": {"boot_args": "staged", "canary": "staged"}})
            self.assertNotIn("not published", str(facts))

    def test_invalid_debugger_plist_does_not_hide_network_class(self):
        network = plistlib.dumps([{"IOObjectClass": "AppleVirtIONetwork", "secret": "not published"}])
        def capture(argv, *_args, **_kwargs):
            if argv[-1] == "IOKernelDebugger":
                return b""
            if argv[-1] == "IONetworkController":
                return network
            raise OSError("optional unavailable")
        with patch.object(b, "capture", capture):
            facts = b.MacPlatform().inventory()
        self.assertIsNone(facts["debugger_count"])
        self.assertEqual(facts["debugger_inventory_status"], "invalid")
        self.assertEqual(facts["network_inventory_status"], "observed")
        self.assertEqual(facts["virtio_network_classes"], ["AppleVirtIONetwork"])
        self.assertNotIn("not published", str(facts))

    def test_empty_ioreg_array_is_observed_zero(self):
        def capture(argv, *_args, **_kwargs):
            if argv[0] == "/usr/sbin/dtrace":
                raise OSError("unavailable")
            return plistlib.dumps([])
        with patch.object(b, "capture", capture):
            facts = b.MacPlatform().inventory()
        self.assertEqual(facts["debugger_count"], 0)
        self.assertEqual(facts["debugger_inventory_status"], "observed")
        self.assertEqual(facts["network_inventory_status"], "observed")
        self.assertTrue(all(value == {"status": "unavailable"} for value in facts["kernel_debug_state"].values()))

    def test_kernel_debug_state_has_only_allowed_numeric_fields(self):
        def capture(argv, *_args, **_kwargs):
            source = argv[-1]
            if "`debug_boot_arg" in source:
                return b"8192\n"
            if "`kdp_flag" in source:
                return b"129\n"
            raise OSError("static symbol unavailable")
        with patch.object(b, "capture", capture):
            facts = b.kernel_debug_state()
        self.assertEqual(facts, {"debug_boot_arg": {"status": "observed", "value": 8192},
                                 "kdp_flag": {"status": "observed", "value": 129},
                                 "send_registered": {"status": "unavailable"}, "receive_registered": {"status": "unavailable"}})
        with patch.object(b, "capture", lambda *_args, **_kwargs: b"secret"):
            invalid = b.kernel_debug_state()
        self.assertTrue(all(value == {"status": "invalid"} for value in invalid.values()))
        self.assertNotIn("secret", str(invalid))

    def test_observation_save_failure_still_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            def save(path, data):
                if path.name == "debug-boot-observed.json":
                    raise OSError("observation storage unavailable")
                self.save(path, data)
            with self.assertRaises(OSError):
                b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(platform.value, original)
            self.assertTrue(json.loads((directory / "debug-boot-restored.json").read_text())["nvram_restored"])

    def test_active_distinguishes_empty_output_from_empty_bootargs(self):
        with patch.object(b, "capture", lambda *_args, **_kwargs: b""):
            with self.assertRaises(ValueError):
                b.MacPlatform().active()
        with patch.object(b, "capture", lambda *_args, **_kwargs: b"\n"):
            self.assertEqual(b.MacPlatform().active(), b"")

    def test_core_finish_does_not_run_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({"boot-args": "preempt=10"})
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.events.clear()
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
            self.assertTrue(facts["nvram_restored"])
            self.assertNotIn("inventory", platform.events)

    def test_optional_inventory_started_marker_prevents_reexecution(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({})
            original_inventory = platform.inventory
            def inventory():
                saved = json.loads((directory / "debug-boot-inventory-started.json").read_text())
                self.assertEqual(saved, {"marker": marker, "current_boot_uuid": "new"})
                return original_inventory()
            with patch.object(platform, "inventory", inventory):
                b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(platform.events, ["inventory"])
            (directory / "debug-boot-inventory-result.json").unlink()
            facts = b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(facts["optional_inventory_status"], "uncertain")
            self.assertEqual(platform.events, ["inventory"])
            facts = b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="future")
            self.assertEqual(facts["optional_inventory_status"], "scope_mismatch")
            self.assertEqual(platform.events, ["inventory"])

    def test_saved_observation_cannot_be_reused_for_another_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.active_value = b"debug=0x2000"
            b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="first")
            self.assertEqual(platform.value, original)
            platform.active_value = b"preempt=10"
            with self.assertRaises(ValueError):
                b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="second")


if __name__ == "__main__":
    unittest.main()
