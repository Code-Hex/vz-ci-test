import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bootargs", Path(__file__).with_name("recovery_bootargs.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class Platform:
    def __init__(self, value):
        self.value, self.events, self.fail_write = value, [], False
        self.active_value = b"preempt=10"

    def read(self):
        return self.value

    def write(self, path):
        self.events.append("write")
        self.value = b.parse_nvram(path.read_bytes())
        if self.fail_write:
            self.fail_write = False
            raise OSError("write response lost")

    def active(self):
        self.events.append("active")
        return self.active_value

    def inventory(self):
        self.events.append("inventory")
        return {"debugger_count": None, "virtio_network_classes": [], "nic_inventory_status": "unsupported"}


class Bootargs(unittest.TestCase):
    def save(self, path, data):
        with path.open("xb") as stream:
            stream.write(data)

    def test_input_and_type_preservation(self):
        for original in ({}, {"boot-args": "preempt=10"}, {"boot-args": b"preempt=10"}, {"boot-args": b""}):
            staged = b.desired(original)
            self.assertEqual(b.debug_mask(staged["boot-args"]), 0x2000)
            if original:
                self.assertIs(type(staged["boot-args"]), type(original["boot-args"]))
        for raw in (b"", b"garbage", plistlib.dumps([]), plistlib.dumps({"boot-args": 1}),
                    plistlib.dumps({"other:boot-args": b""})):
            with self.assertRaises(ValueError):
                b.parse_nvram(raw)
        for value in ("debug=0", "_panicd_ip=1.1.1.1", "_router_ip=1.1.1.1", "_panicd_corename=x"):
            with self.assertRaises(ValueError):
                b.desired({"boot-args": value})

    def test_stage_saved_before_write_and_restore_before_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            original = {"boot-args": b"preempt=10"}
            platform = Platform(original)
            marker = {"baseline": "old", "nonce": "n"}
            def save(path, data):
                self.save(path, data)
                platform.events.append(path.name)
            b.stage(directory, marker, platform, save, lambda _p: platform.events.append("sync"))
            self.assertLess(platform.events.index("debug-boot-stage.json"), platform.events.index("write"))
            self.assertLess(platform.events.index("sync"), platform.events.index("write"))
            platform.events.clear()
            platform.active_value = b"preempt=10 debug=0x2000"
            facts = b.finish(directory, marker, platform, save, lambda _p: None)
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
                    b.stage(directory, {"baseline": "old", "nonce": "n"}, platform, self.save, lambda _p: None)
                self.assertEqual(platform.value, original)
                self.assertTrue(json.loads((directory / "debug-boot-restored.json").read_text())["nvram_restored"])

    def test_invalid_active_mask_still_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), {"baseline": "old", "nonce": "n"}
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.active_value = b"debug=invalid"
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None)
            self.assertIsNone(facts["active_debug_mask"])
            self.assertTrue(facts["nvram_restored"])
            self.assertEqual(platform.value, original)

    def test_identity_or_unexpected_nvram_prevents_overwrite_and_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), {"baseline": "old", "nonce": "n"}
            platform = Platform({"boot-args": "preempt=10"})
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.value = {"boot-args": "other=1"}
            platform.events.clear()
            for identity in (marker, {"baseline": "other", "nonce": "n"}):
                with self.assertRaises(ValueError):
                    b.finish(directory, identity, platform, self.save, lambda _p: None)
            self.assertNotIn("write", platform.events)
            self.assertNotIn("inventory", platform.events)

    def test_capture_rejects_oversized_child_output(self):
        with self.assertRaises(ValueError):
            b.capture([sys.executable, "-c", "print('oversized')"], limit=2)

    def test_unstaged_rollback_only_accepts_clean_nvram(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), {"baseline": "old", "nonce": "n"}
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


if __name__ == "__main__":
    unittest.main()
