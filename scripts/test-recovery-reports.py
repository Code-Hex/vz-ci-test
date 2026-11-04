import base64
import gzip
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("reports", Path(__file__).with_name("recovery_reports.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Reports(unittest.TestCase):
    def test_inventory_stable_selection_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "Kernel-old.ips"
            old.write_text(json.dumps({"panicString": "old", "kernelUUID": r.KERNEL_UUID}))
            baseline = r.inventory([root])
            report = root / "Kernel-new.ips"
            report.write_text(json.dumps({"bug_type": "210"}) + "\n" + json.dumps({"panicString": "panic(cpu 0): dtrace: panic action at probe dtrace:::BEGIN (ecb 0x1234)", "kernelUUID": r.KERNEL_UUID}))
            capture = r.select_stable([root], baseline, interval=0)
            self.assertEqual(capture["sha256"], r.digest(report.read_bytes()))
            (root / "Kernel-another.ips").write_bytes(report.read_bytes())
            with self.assertRaises(ValueError):
                r.select_stable([root], baseline, interval=0)

    def test_wrong_uuid_signature_and_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "Kernel-new.ips"
            path.write_text(json.dumps({"panicString": "different", "kernelUUID": r.KERNEL_UUID}))
            with self.assertRaises(ValueError):
                r.select_stable([root], {}, interval=0)
            with self.assertRaises(ValueError):
                r.match_report(json.dumps({"panicString": "dtrace: panic action at probe dtrace:::BEGIN (ecb 0x1234)", "kernelUUID": "wrong"}).encode(), ".ips")
            valid = json.dumps({"panicString": "dtrace: panic action at probe dtrace:::BEGIN (ecb 0x1234)", "kernelUUID": r.KERNEL_UUID})
            with self.assertRaises(ValueError):
                r.match_report(("{}\n" + valid + "\n{}").encode(), ".ips")
            with self.assertRaises(ValueError):
                r.match_report(json.dumps({"panicString": "unrelated", "comment": valid, "kernelUUID": r.KERNEL_UUID}).encode(), ".ips")

    def test_panic_string_kernel_uuid_and_header_only(self):
        header = "panic(cpu 2 caller 0xffffff8001234567): dtrace: panic action at probe dtrace:::BEGIN (ecb 0x1234)"
        message = header + "\nKernel UUID: " + r.KERNEL_UUID
        self.assertTrue(r.match_report(json.dumps({"panicString": message}).encode(), ".ips"))
        with self.assertRaises(ValueError):
            r.match_report(json.dumps({"panicString": message, "kernelUUID": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"}).encode(), ".ips")
        with self.assertRaises(ValueError):
            r.match_report(json.dumps({"panicString": "panic(cpu 2): unrelated\n" + header, "kernelUUID": r.KERNEL_UUID}).encode(), ".ips")

    def test_force_reset_requires_exact_run_marker(self):
        marker = "vz-force-reset:123:1:" + "a" * 64
        message = "panic(cpu 2 caller 0xffffff8001234567): userspace panic: " + marker
        report = json.dumps({"panicString": message, "kernelUUID": r.KERNEL_UUID}).encode()
        self.assertTrue(r.match_report(report, ".ips", "panic-force-reset", marker))
        with self.assertRaises(ValueError):
            r.match_report(json.dumps({"panicString": message + " extra", "kernelUUID": r.KERNEL_UUID}).encode(), ".ips", "panic-force-reset", marker)
        with self.assertRaises(ValueError):
            r.match_report(report, ".ips", "panic-force-reset", marker[:-1] + "b")
        with self.assertRaises(ValueError):
            r.match_report(report, ".ips", "panic-control")
        with self.assertRaises(ValueError):
            r.match_report(json.dumps({"panicString": "panic(cpu 0): unrelated\n" + message, "kernelUUID": r.KERNEL_UUID}).encode(), ".ips", "panic-force-reset", marker)

    def test_synthetic_cms_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key, cert = root / "key.pem", root / "cert.pem"
            subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=synthetic", "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            metadata = {"run": "123", "nonce": "ab", "before": "one", "after": "two"}
            result = r.encrypt_bundle(cert.read_bytes(), metadata, b"synthetic report")
            self.assertLessEqual(len(result["ciphertext"].encode()), 58000)
            decoded = subprocess.check_output(["/usr/bin/openssl", "cms", "-decrypt", "-inform", "DER", "-recip", str(cert), "-inkey", str(key)], input=base64.b64decode(result["ciphertext"]))
            bundle = json.loads(gzip.decompress(decoded))
            self.assertEqual(base64.b64decode(bundle["report_base64"]), b"synthetic report")
            self.assertEqual(bundle["metadata"], metadata)
            self.assertEqual(result["cipher_sha256"], r.digest(base64.b64decode(result["ciphertext"])))


if __name__ == "__main__":
    unittest.main()
