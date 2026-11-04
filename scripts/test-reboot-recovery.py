import importlib.util
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("reboot-recovery.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Recovery(unittest.TestCase):
    def cleanup_cli(self, *, check_id="126520221299", token="test-job-token", status="in_progress", system="Linux", repo="Code-Hex/vz-ci-test"):
        old_sha = "a" * 40
        check = {"id": 126520221299, "name": "Runner recovery 41814026408", "head_sha": old_sha,
                 "external_id": "41814026408/1/" + old_sha, "app": {"slug": "github-actions", "id": 15368},
                 "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/126520221299", "status": status}
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": repo, "GITHUB_RUN_ID": "999",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b" * 40, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
               "GITHUB_TOKEN": token, "RECOVERY_CLEANUP_CHECK_ID": check_id}
        calls = []

        def api(method, url, credential, payload=None):
            self.assertEqual(credential, token)
            self.assertEqual(url, r.CHECKS + "/126520221299")
            calls.append((method, payload))
            if method == "GET":
                return check
            self.assertEqual(method, "PATCH")
            return {}

        def command(command):
            return {("/usr/bin/uname", "-s"): system, ("/usr/bin/uname", "-m"): "x86_64",
                    ("/usr/sbin/sysctl", "-n", "kern.uuid"): r.KERNEL_UUID}[tuple(command)]

        def forbidden(*_args, **_kwargs):
            self.fail("cleanup entered controller or sudo path")

        with patch.dict(os.environ, env, clear=True), patch.object(r.sys, "argv", ["reboot-recovery.py", "cleanup"]), \
                patch.object(r, "api", api), patch.object(r, "command_output", command), \
                patch.object(r, "controller", forbidden), patch.object(r, "sudo_call", forbidden), \
                contextlib.redirect_stdout(io.StringIO()):
            r.main()
        return calls

    def test_cleanup_cli_only_cancels_verified_old_check(self):
        self.assertEqual(self.cleanup_cli(), [("GET", None), ("PATCH", {
            "status": "completed", "conclusion": "cancelled",
            "output": {"title": "Prior recovery attempt cancelled", "summary": "Superseded recovery attempt."}})])

    def test_cleanup_cli_completed_check_needs_no_patch(self):
        self.assertEqual(self.cleanup_cli(status="completed"), [("GET", None)])

    def test_cleanup_cli_requires_token_id_and_linux_context(self):
        for options in ({"token": ""}, {"check_id": ""}, {"check_id": "../126520221299"},
                        {"system": "Darwin"}, {"repo": "other"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.cleanup_cli(**options)

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

    def test_force_preflight_errors_are_whitelisted(self):
        self.assertEqual(r.safe_force_preflight_error('secret\n{"event":"force_reset_guard_failed","token":"secret"}'), {"event": "force_reset_guard_failed"})
        self.assertEqual(r.safe_force_preflight_error('{"event":"force_reset_symbol_unavailable"}'), {"event": "force_reset_symbol_unavailable"})
        self.assertIsNone(r.safe_force_preflight_error('{"event":"secret"}'))
        self.assertIsNone(r.safe_force_preflight_error('{"event":[]}'))

    def test_force_return_diagnostic_is_numeric_and_redacted(self):
        text = 'secret\n{"event":"force_reset_unexpected_return","result":-1,"errno":1,"token":"secret"}\n'
        self.assertEqual(r.safe_force_return(text), {"event": "force_reset_unexpected_return", "result": -1, "errno": 1})
        self.assertIsNone(r.safe_force_return('{"event":"force_reset_unexpected_return","result":"secret","errno":1}'))
        self.assertIsNone(r.safe_force_return('secret'))

    def test_root_error_kind_is_whitelisted(self):
        self.assertEqual(r.root_error_kind('noise SECRET\n{"event":"recovery_error","kind":"ValueError"}\n'), "ValueError")
        self.assertEqual(r.root_error_kind('{"event":"recovery_error","kind":"SECRET"}'), "unknown")
        self.assertEqual(r.root_error_kind('{"event":"other","kind":"ValueError"}'), "unknown")
        self.assertEqual(r.root_error_kind('unstructured SECRET'), "unknown")

    def test_force_reset_marker_and_guard(self):
        ctx = {"actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1",
               "sha": "a" * 40, "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted", "trigger": "panic-force-reset"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, trigger="panic-control"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, trigger="reboot"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(dict(ctx, trigger="unknown"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertEqual(r.force_marker(ctx, "b" * 64), "vz-force-reset:123:1:" + "b" * 64)
        with self.assertRaises(ValueError):
            r.force_marker(ctx, "not-a-nonce")

    def test_only_changed_nonempty_boot_is_recovery(self):
        self.assertFalse(r.reboot_observed("abc", "abc"))
        self.assertFalse(r.reboot_observed("abc", ""))
        self.assertTrue(r.reboot_observed("abc", "def"))

    def test_debug_boot_request_is_normal_reboot_only(self):
        self.assertTrue(r.recovery_bootargs.requested("1", "reboot"))
        self.assertFalse(r.recovery_bootargs.requested("", "reboot"))
        for value, trigger in (("true", "reboot"), ("1", "panic-control"), ("1", "panic-force-reset")):
            with self.assertRaises(ValueError):
                r.recovery_bootargs.requested(value, trigger)

    def test_debug_boot_proof_requires_mask_restore_and_mode_binding(self):
        ctx = {"run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True}
        pending = {"nonce": "n", "baseline_boot_uuid": "old"}
        data = {"protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx),
                "nonce": "n", "baseline_boot_uuid": "old", "current_boot_uuid": "new", "debug_boot": True,
                "debug_boot_facts": {"active_debug_mask": 0x2000, "nvram_restored": True,
                                     "debugger_count": None, "nic_inventory_status": "unsupported"}}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        for facts in ({}, {"active_debug_mask": 0x2000, "nvram_restored": False},
                      {"active_debug_mask": 0x400, "nvram_restored": True}):
            self.assertFalse(r.boot_proof_matches(dict(data, debug_boot_facts=facts), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, debug_boot=False), pending, ctx))
        self.assertFalse(r.boot_proof_matches(data, pending, dict(ctx, debug_boot=False)))

    def test_debug_reboot_failures_restore_once_without_reboot(self):
        for failure in ("stage_response", "stdout", "sync"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                original = {"boot-args": b"preempt=10"}
                state, events = dict(original), []
                class Platform:
                    def read(self):
                        return state.copy()
                    def active(self):
                        return b"preempt=10"
                    def write(self, path):
                        state.clear()
                        state.update(r.recovery_bootargs.parse_nvram(path.read_bytes()))
                        events.append("restore" if state == original else "stage")
                platform, marker = Platform(), {"baseline": "old", "nonce": "n"}
                def sudo(operation, _payload, **_kwargs):
                    if operation == "verify-root":
                        return "ready"
                    if operation == "debug-stage-root":
                        r.recovery_bootargs.stage(directory, marker, platform, r.private_write, r.sync_directory)
                        if failure == "stage_response":
                            raise RuntimeError("stage reply lost")
                        return "staged"
                    self.assertEqual(operation, "debug-restore-root")
                    r.recovery_bootargs.rollback(directory, marker, platform, r.private_write, r.sync_directory)
                    return "restored"
                class Output(io.StringIO):
                    def write(self, value):
                        if failure == "stdout" and value == "staged":
                            raise BrokenPipeError("closed stdout")
                        return super().write(value)
                def sync():
                    if failure == "sync":
                        raise OSError("sync failed")
                def forbidden(*_args, **_kwargs):
                    self.fail("failed debug stage reached reboot")
                ctx = {"trigger": "reboot", "debug_boot": True}
                with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                        patch.object(r, "context_from_env", lambda: ctx), patch.object(r, "require_context", lambda *_: None), \
                        patch.object(r, "sudo_call", sudo), patch.object(r.os, "sync", sync), \
                        patch.object(r.subprocess, "run", forbidden), contextlib.redirect_stdout(Output()):
                    with self.assertRaises((OSError, RuntimeError)):
                        r.main()
                self.assertEqual(events, ["stage", "restore"])
                self.assertEqual(state, original)

    def test_debug_rollback_refuses_another_boot(self):
        config = {"context": {"debug_boot": True}, "debug_boot": True, "baseline": "old"}
        with patch.object(r, "root_only", lambda: None), patch.object(r, "require_context", lambda *_: None), \
                patch.object(r, "root_dir", lambda _: Path("/unused")), patch.object(r, "load_config", lambda _: config), \
                patch.object(r, "boot_uuid", lambda: "new"):
            with self.assertRaises(ValueError):
                r.debug_restore_root({"context": config["context"]})

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

    def test_panic_proof_requires_matching_ciphertext(self):
        import base64
        import hashlib
        ctx = {"run_id": "123", "attempt": "1", "sha": "a" * 40, "trigger": "panic-control"}
        pending = {"nonce": "b" * 64, "baseline_boot_uuid": "old", "cert_fingerprint": "c" * 64}
        data = {"protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "boot_observed", "nonce": pending["nonce"],
                "baseline_boot_uuid": "old", "current_boot_uuid": "new", "trigger": "panic-control",
                "cert_fingerprint": pending["cert_fingerprint"], "capture_state": "captured", "cipher_sha256": hashlib.sha256(b"cipher").hexdigest()}
        encoded = base64.b64encode(b"cipher").decode()
        self.assertTrue(r.panic_envelope_matches(data, encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(data, base64.b64encode(b"other").decode(), pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, capture_state="missing"), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, cert_fingerprint="d" * 64), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, trigger="reboot"), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, baseline_boot_uuid="wrong"), encoded, pending, ctx))
        force_ctx = dict(ctx, trigger="panic-force-reset")
        self.assertTrue(r.panic_envelope_matches(dict(data, trigger="panic-force-reset"), encoded, pending, force_ctx))
        self.assertFalse(r.panic_envelope_matches(data, encoded, pending, force_ctx))

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
