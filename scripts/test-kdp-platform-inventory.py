import importlib.util
from pathlib import Path
import plistlib
import unittest

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("kdp-platform-inventory.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Inventory(unittest.TestCase):
    def test_bootargs_only_selected_information(self):
        self.assertEqual(r.parse_bootargs('secret=private debug=0x144 _panicd_ip=192.0.2.3 _router_ip=192.0.2.4'),
                         {"debug_masks": [324], "panicd_present": True, "router_present": True})
        self.assertEqual(r.parse_bootargs('debug=invalid debug=8 -_panicd_ip unrelated'),
                         {"debug_masks": [8], "panicd_present": True, "router_present": False})

    def test_sip_strict_whitelist(self):
        self.assertEqual(r.parse_sip('System Integrity Protection status: enabled.\nKernel Debugging: disabled.\nsecret'),
                         {"sip": "enabled", "kernel_debugging": "disabled"})
        self.assertEqual(r.parse_sip('System Integrity Protection status: custom configuration.\n'),
                         {"sip": "custom", "kernel_debugging": "unknown"})
        self.assertEqual(r.parse_sip('unrecognized: private\n'),
                         {"sip": "unknown", "kernel_debugging": "unknown"})

    def test_plist_only_allowed_fields_and_bounded_identifiers(self):
        obj = [{"IOClass": "AppleNIC", "IOInterfaceName": "en0", "IOMACAddress": "secret",
                "IORegistryEntryChildren": [{"IOProviderClass": "IOPCIDevice", "serial": "secret"},
                                            {"IOClass": "bad/path"}]}]
        result = r.parse_network(plistlib.dumps(obj))
        self.assertEqual(result, [{"IOClass": "AppleNIC", "IOInterfaceName": "en0"},
                                  {"IOProviderClass": "IOPCIDevice"}])
        self.assertNotIn("secret", str(result))

    def test_watchdog_and_nvram_controller_only_safe_fields(self):
        raw = plistlib.dumps([{"IOClass": "WatchdogImpl", "IOProviderClass": "AppleSMC",
                              "IOWatchDogEnabled": True, "Serial": "hidden", "Path": "private"},
                             {"IOClass": "invalid/name", "IOWatchDogEnabled": 1}])
        self.assertEqual(r.parse_devices(raw, True), {"count": 2, "nodes": [
            {"IOClass": "WatchdogImpl", "IOProviderClass": "AppleSMC", "IOWatchDogEnabled": True}, {}]})
        self.assertEqual(r.parse_devices(plistlib.dumps([]), False), {"count": 0, "nodes": []})
        with self.assertRaises(ValueError):
            r.parse_devices(b"", True)

    def test_single_panic_key_type_and_size_only(self):
        raw = plistlib.dumps({"aapl,panic-info": b"sensitive"})
        self.assertEqual(r.parse_panic_nvram(raw), {"type": "data", "size": 9})
        with self.assertRaises(ValueError):
            r.parse_panic_nvram(plistlib.dumps({"aapl,panic-info": b"x", "other": b"secret"}))
        with self.assertRaises(ValueError):
            r.parse_panic_nvram(b"")

    def test_debugger_count_only(self):
        self.assertEqual(r.count_debuggers(plistlib.dumps([{"serial": "secret"}, {}])), 2)
        with self.assertRaises(ValueError):
            r.count_debuggers(plistlib.dumps({"unexpected": 1}))


if __name__ == "__main__":
    unittest.main()
