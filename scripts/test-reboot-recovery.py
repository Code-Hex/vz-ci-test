import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("reboot-recovery.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Recovery(unittest.TestCase):
    def test_guard(self):
        ctx = {"actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "2",
               "sha": "a" * 40, "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        for key, value in [("actions", "false"), ("repo", "other"), ("run_id", "../1"),
                           ("attempt", "0"), ("sha", "bad"), ("event", "push")]:
            self.assertFalse(r.valid_context(dict(ctx, **{key: value}), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(ctx, "Darwin", "arm64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(ctx, "Darwin", "x86_64", "bad"))

    def test_root_error_kind_is_whitelisted(self):
        self.assertEqual(r.root_error_kind('noise SECRET\n{"event":"recovery_error","kind":"ValueError"}\n'), "ValueError")
        self.assertEqual(r.root_error_kind('{"event":"recovery_error","kind":"SECRET"}'), "unknown")
        self.assertEqual(r.root_error_kind('{"event":"other","kind":"ValueError"}'), "unknown")
        self.assertEqual(r.root_error_kind('unstructured SECRET'), "unknown")

    def test_only_changed_nonempty_boot_is_recovery(self):
        self.assertFalse(r.reboot_observed("abc", "abc"))
        self.assertFalse(r.reboot_observed("abc", ""))
        self.assertTrue(r.reboot_observed("abc", "def"))

    def test_rsa_oaep_sha256_roundtrip_and_key_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "key.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(private)], check=True, stderr=subprocess.DEVNULL)
            public = subprocess.check_output(["openssl", "pkey", "-in", str(private), "-pubout"])
            ciphertext = r.encrypt_token(public, "test-job-token")
            self.assertNotIn(b"test-job-token", ciphertext)
            self.assertEqual(r.decrypt_token(private, ciphertext), "test-job-token")
            small = Path(tmp) / "small.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(small)], check=True, stderr=subprocess.DEVNULL)
            invalid = subprocess.check_output(["openssl", "pkey", "-in", str(small), "-pubout"])
            with self.assertRaises(ValueError):
                r.encrypt_token(invalid, "test-job-token")

    def test_sealed_retry_and_boot_proof_match_nonce_and_baseline(self):
        ctx = {"run_id": "123", "attempt": "2", "sha": "a" * 40}
        pending = {"nonce": "b" * 64, "baseline_boot_uuid": "first", "ciphertext": "cipher"}
        data = {"protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "sealed_token", **pending}
        self.assertTrue(r.sealed_matches(data, pending, ctx))
        self.assertFalse(r.sealed_matches(dict(data, ciphertext="other"), pending, ctx))
        proof = {"protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "boot_observed",
                 "nonce": pending["nonce"], "baseline_boot_uuid": "first", "current_boot_uuid": "second"}
        armed = {"protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "armed", "nonce": pending["nonce"], "baseline_boot_uuid": "first"}
        self.assertTrue(r.armed_matches(armed, pending, ctx))
        self.assertFalse(r.armed_matches(dict(armed, baseline_boot_uuid="other"), pending, ctx))
        self.assertTrue(r.boot_proof_matches(proof, pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, nonce="wrong"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, baseline_boot_uuid="other"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, current_boot_uuid="first"), pending, ctx))

    def test_old_check_cleanup_validates_canonical_binding(self):
        old_sha = "a" * 40
        old = {"id": 126478800449, "name": "Runner recovery 41801686112", "head_sha": old_sha,
               "external_id": "41801686112/1/" + old_sha, "app": {"slug": "github-actions", "id": 15368},
               "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/126478800449", "status": "in_progress"}
        current = {"run_id": "999", "attempt": "1", "sha": "b" * 40}
        self.assertTrue(r.cleanup_eligible(old, "126478800449", current))
        self.assertFalse(r.cleanup_eligible(old, "0", current))
        self.assertFalse(r.cleanup_eligible(old, "../126478800449", current))
        self.assertFalse(r.cleanup_eligible(old, "126478800449", dict(current, run_id="41801686112")))
        self.assertFalse(r.cleanup_eligible(dict(old, head_sha="b" * 40), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, status="completed"), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, status="unknown"), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, app={"id": 9, "slug": "github-actions"}), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, details_url="https://evil.example"), "126478800449", current))

    def test_binding_exact_and_no_duplicate(self):
        ctx = {"run_id": "123", "attempt": "2", "sha": "a" * 40}
        check = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx),
                 "head_sha": ctx["sha"], "app": {"slug": "github-actions", "id": 15368},
                 "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9", "status": "in_progress"}
        self.assertEqual(r.select_check([check], ctx)["id"], 9)
        self.assertIsNone(r.select_check([dict(check, external_id="wrong")], ctx))
        self.assertIsNone(r.select_check([dict(check, app={"id": 7, "slug": "github-actions"})], ctx))
        self.assertIsNone(r.select_check([dict(check, details_url="https://example.com")], ctx))
        self.assertIsNone(r.select_check([dict(check, details_url="https://github.com/Code-Hex/vz-ci-test/runs/10")], ctx))
        self.assertIsNone(r.select_check([dict(check, id="9")], ctx))
        with self.assertRaises(ValueError):
            r.select_check([check, check], ctx)


if __name__ == "__main__":
    unittest.main()
