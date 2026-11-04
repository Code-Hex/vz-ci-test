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

    def test_quick_trigger_and_return_facts_are_bound_and_redacted(self):
        ctx = {"actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1", "sha": "a" * 40,
               "ref": "refs/heads/main", "event": "workflow_dispatch", "runner_environment": "github-hosted",
               "trigger": "reboot-quick", "debug_boot": False}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(dict(ctx, debug_boot=True), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.panic_mode(ctx))
        fact = r.safe_quick_return('raw-secret\n{"event":"quick_reboot_unexpected_return","result":-1,"errno":1,"token":"raw-secret"}')
        self.assertEqual(fact, {"event": "quick_reboot_unexpected_return", "result": -1, "errno": 1})
        self.assertIsNone(r.safe_quick_return('{"event":"quick_reboot_unexpected_return","result":true,"errno":1}'))
        self.assertFalse(r.mode_matches({"trigger": "reboot"}, {}, ctx))
        pending = {"nonce": "n", "baseline_boot_uuid": "old"}
        data = {"protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx),
                "nonce": "n", "baseline_boot_uuid": "old", "current_boot_uuid": "new", "trigger": "reboot-quick"}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, phase="quick_prepared"), pending, ctx))

    def test_quick_main_only_routes_to_root_rpc(self):
        calls = []
        def sudo(operation, *_args, **kwargs):
            calls.append((operation, kwargs["timeout"]))
            return ""
        def forbidden(*_args, **_kwargs):
            self.fail("quick trigger used the normal reboot path")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "trigger"]), \
                patch.object(r, "context_from_env", lambda: {"trigger": "reboot-quick", "debug_boot": False}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, [("quick-execute-root", 90)])

    def test_quick_prepared_ack_precedes_execute_and_return_completes_failure(self):
        for acknowledged in (True, False):
            with self.subTest(acknowledged=acknowledged), tempfile.TemporaryDirectory() as tmp:
                directory, events, output = Path(tmp), [], io.StringIO()
                ctx = {"actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1", "sha": "a" * 40,
                       "ref": "refs/heads/main", "event": "workflow_dispatch", "runner_environment": "github-hosted",
                       "trigger": "reboot-quick", "debug_boot": False}
                helper = directory / "reboot-quick"
                helper.write_bytes(b"synthetic helper")
                config = {"context": ctx, "baseline": "old", "nonce": "n", "check_id": 9, "cert_fingerprint": "",
                          "helper_sha256": r.hashlib.sha256(helper.read_bytes()).hexdigest()}
                r.private_write(directory / "token", b"private-token")
                initial = {"protocol": "vz-recovery-v1", "phase": "armed", "binding": r.binding(ctx), "nonce": "n",
                           "baseline_boot_uuid": "old", "trigger": "reboot-quick", "debug_boot": False, "cert_fingerprint": ""}
                check = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                         "app": {"id": 15368, "slug": "github-actions"}, "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                         "status": "in_progress", "output": {"summary": r.json.dumps(initial)}}
                def api(method, _url, token, payload=None, **_kwargs):
                    self.assertEqual(token, "private-token")
                    if method == "GET":
                        events.append("ack" if "prepared" in events else "get")
                        result = dict(check)
                        if "prepared" in events and not acknowledged:
                            result["status"] = "completed"
                        return result
                    check.update(payload)
                    events.append("failed" if payload.get("status") == "completed" else "prepared")
                    return check
                def run(command, **kwargs):
                    self.assertEqual(command, [str(helper), "preflight"])
                    self.assertTrue((directory / "quick-trigger.json").exists())
                    self.assertEqual(kwargs["env"]["RECOVERY_TRIGGER"], "reboot-quick")
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    events.append("preflight")
                    return subprocess.CompletedProcess(command, 0, '{"event":"quick_reboot_preflight","flags":1024,"permission_verified":false}', '')
                class Child:
                    returncode = 70
                    def communicate(self, timeout):
                        return ('raw-secret\n{"event":"quick_reboot_unexpected_return","result":-1,"errno":1}', '')
                def popen(command, **kwargs):
                    self.assertEqual(command, [str(helper), "execute"])
                    self.assertEqual(events[-1], "ack")
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    events.append("execute")
                    return Child()
                with patch.object(r, "root_only", lambda: None), patch.object(r, "require_context", lambda *_: None), \
                        patch.object(r, "root_dir", lambda _: directory), patch.object(r, "load_config", lambda _: config), \
                        patch.object(r, "verify_root", lambda _: None), patch.object(r, "boot_uuid", lambda: "old"), \
                        patch.object(r.os, "sync", lambda: events.append("sync")), patch.object(r.subprocess, "run", run), \
                        patch.object(r.subprocess, "Popen", popen), patch.object(r, "api", api), contextlib.redirect_stdout(output):
                    with self.assertRaises((RuntimeError, ValueError)):
                        r.quick_execute_root({"context": ctx})
                self.assertEqual(events[:2], ["sync", "preflight"])
                self.assertNotIn("raw-secret", output.getvalue())
                if acknowledged:
                    self.assertEqual(events[-2:], ["execute", "failed"])
                    self.assertEqual(check["conclusion"], "failure")
                else:
                    self.assertNotIn("execute", events)

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
                "debug_boot_facts": {"active_debug_mask": 0x2000, "active_bootargs_status": "observed_debug", "nvram_restored": True,
                                     "current_boot_uuid": "new",
                                     "debugger_count": None, "nic_inventory_status": "unsupported"}}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        core = dict(data, phase="boot_core")
        self.assertFalse(r.boot_proof_matches(core, pending, ctx))
        for facts in ({}, {"active_debug_mask": 0x2000, "nvram_restored": False},
                      {"active_debug_mask": 0x400, "nvram_restored": True},
                      {"active_debug_mask": 0x2000, "active_bootargs_status": "invalid", "nvram_restored": True}):
            self.assertFalse(r.boot_proof_matches(dict(data, debug_boot_facts=facts), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, debug_boot=False), pending, ctx))
        self.assertFalse(r.boot_proof_matches(data, pending, dict(ctx, debug_boot=False)))
        self.assertFalse(r.boot_proof_matches(dict(data, current_boot_uuid="another"), pending, ctx))

    def test_debug_parent_shutdown_cannot_restore_or_reboot(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            if operation == "verify-root":
                return "ready"
            self.assertEqual(operation, "debug-request-root")
            raise KeyboardInterrupt()
        def forbidden(*_args, **_kwargs):
            self.fail("runner parent performed debug mutation or reboot")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"trigger": "reboot", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root"])

    def test_debug_parent_waits_after_request_without_mutation(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return "ready"
        def forbidden(*_args, **_kwargs):
            self.fail("runner parent mutated debug state")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"trigger": "reboot", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                patch.object(r.time, "sleep", lambda seconds: calls.append(("wait", seconds))), contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root", ("wait", 90)])

    def owner_fixture(self, directory):
        config = {"context": {"run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True, "trigger": "reboot"},
                  "debug_boot": True, "baseline": "old", "nonce": "n", "debug_source_identity": r.debug_source_identity()}
        original = {"boot-args": b"preempt=10"}
        class Platform:
            fail_write = False
            def __init__(self):
                self.value = original.copy()
                self.active_value = b"preempt=10"
                self.events = []
            def read(self):
                return self.value.copy()
            def active(self):
                return self.active_value
            def write(self, path):
                self.events.append("write")
                self.value = r.recovery_bootargs.parse_nvram(path.read_bytes())
                if self.fail_write:
                    self.fail_write = False
                    raise OSError("write response lost")
            def inventory(self):
                self.events.append("inventory")
                return {"nic_inventory_status": "unsupported"}
        r.debug_event(directory, config, "request", "old")
        return config, Platform(), original

    def test_owner_preintent_failure_restores_without_reboot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            platform.fail_write = True
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("preintent reboot")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            self.assertFalse((directory / "debug-reboot-intent.json").exists())
            self.assertTrue((directory / "debug-reboot-aborted.json").exists())

    def test_owner_postintent_timeout_or_signal_never_kills_restores_or_retries(self):
        for failure in (subprocess.TimeoutExpired("reboot", 15), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                calls = []
                class Child:
                    pid = 1234
                    def wait(self, timeout):
                        raise failure
                    def kill(self):
                        raise AssertionError("postintent kill")
                def popen(*_args, **_kwargs):
                    calls.append("reboot")
                    return Child()
                with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                        patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), patch.object(r.subprocess, "Popen", popen):
                    r.debug_owner(directory, config, "old")
                    r.debug_owner(directory, config, "old")
                self.assertNotEqual(platform.value, original)
                self.assertEqual(calls, ["reboot"])
                self.assertTrue((directory / "debug-reboot-intent.json").exists())
                self.assertFalse((directory / "debug-boot-restored.json").exists())

    def test_owner_orphan_stage_restores_without_reboot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            r.recovery_bootargs.stage(directory, r.debug_boot_marker(config), platform, r.private_write, r.sync_directory)
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("orphan stage reboot")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            record = r.read_debug_event(directory, config, "aborted")
            self.assertEqual(record["reason"], "orphan_stage")
            self.assertEqual(record["nvram_before_rollback"], "staged")

    def test_owner_returned_request_is_immutable_and_never_reissued(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, _original = self.owner_fixture(directory)
            request = directory / "debug-reboot-request.json"
            first = request.read_bytes()
            r.debug_event(directory, config, "request", "old", reason="interrupted")
            self.assertEqual(request.read_bytes(), first)
            calls = []
            def reboot():
                calls.append("reboot")
                return {"returncode": 0, "reboot_pid": 1234}
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), patch.object(r, "debug_reboot_child", reboot):
                r.debug_owner(directory, config, "old")
                r.debug_owner(directory, config, "old")
            self.assertEqual(calls, ["reboot"])
            self.assertEqual(r.read_debug_event(directory, config, "returned")["returncode"], 0)
            self.assertFalse((directory / "debug-boot-restored.json").exists())

    def test_newboot_core_ack_precedes_inventory_and_failed_ack_skips_it(self):
        for acknowledged, restored in ((True, True), (False, True), (True, False)):
            with self.subTest(acknowledged=acknowledged, restored=restored), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                config["check_id"] = 9
                r.recovery_bootargs.stage(directory, r.debug_boot_marker(config), platform, r.private_write, r.sync_directory)
                platform.active_value = b"preempt=10 debug=0x2000"
                platform.events.clear()
                r.private_write(directory / "token", b"test-token")
                r.private_write(directory / "ready.json", r.json.dumps({"baseline": "old", "nonce": "n", "preboot_patch": True}).encode())
                output = {}
                final_conclusions = []
                original_finish = r.recovery_bootargs.finish
                def finish(*args, **kwargs):
                    if not restored:
                        raise OSError("restoration unavailable")
                    return original_finish(*args, **kwargs)
                def api(method, _url, _token, payload=None, **_kwargs):
                    if method == "PATCH" and payload.get("status") == "in_progress":
                        platform.events.append("core_patch")
                        output.update(payload["output"])
                        return {}
                    if method == "GET":
                        platform.events.append("core_ack")
                        ctx = config["context"]
                        return {"id": 9, "name": "Runner recovery " + ctx["run_id"], "head_sha": ctx["sha"],
                                "external_id": r.binding(ctx), "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                                "app": {"id": 15368 if acknowledged else 0, "slug": "github-actions"},
                                "status": "in_progress", "conclusion": None, "output": output.copy()}
                    platform.events.append("final_patch")
                    final_conclusions.append(payload["conclusion"])
                    error = r.urllib.error.HTTPError("https://api.github.com", 401, "test refusal", {}, None)
                    self.addCleanup(error.close)
                    raise error
                with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: "new"), \
                        patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), patch.object(r, "api", api), \
                        patch.object(r.recovery_bootargs, "finish", finish), \
                        patch.object(r, "debug_owner", lambda *_: self.fail("newboot invoked oldboot owner")):
                    r.collect(directory)
                if restored:
                    self.assertEqual(platform.value, original)
                    self.assertLess(platform.events.index("write"), platform.events.index("core_patch"))
                self.assertTrue((directory / "debug-boot-core.json").exists())
                self.assertEqual(r.json.loads((directory / "debug-boot-core.json").read_text())["facts"]["nvram_restored"], restored)
                if acknowledged and restored:
                    self.assertLess(platform.events.index("core_ack"), platform.events.index("inventory"))
                    self.assertLess(platform.events.index("inventory"), platform.events.index("final_patch"))
                    self.assertEqual(final_conclusions, ["success"])
                elif acknowledged:
                    self.assertNotIn("inventory", platform.events)
                    self.assertEqual(final_conclusions, ["failure"])
                else:
                    self.assertNotIn("inventory", platform.events)
                    self.assertNotIn("final_patch", platform.events)

    def test_default_reboot_path_still_uses_existing_command(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return "ready"
        def run(command, **kwargs):
            calls.append((command, kwargs))
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"trigger": "reboot", "debug_boot": False}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", lambda: calls.append("sync")), patch.object(r.subprocess, "run", run), \
                contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, ["verify-root", "sync", (["/usr/bin/sudo", "-n", "/sbin/reboot"], {"check": True, "timeout": 15})])

    def test_debug_controller_stop_does_not_overwrite_new_core_after_stale_get(self):
        ctx = {"run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True}
        armed = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                 "app": {"id": 15368, "slug": "github-actions"}, "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                 "status": "in_progress", "output": {"summary": '{"phase":"armed"}'}}
        core = {"title": "Boot core recovered", "summary": '{"phase":"boot_core","immutable_fact":true}'}
        server, patches = {"output": armed["output"]}, []
        def api(method, _url, _token, payload=None, **_kwargs):
            if method == "GET":
                server["output"] = core.copy()
                return armed
            self.assertEqual(method, "PATCH")
            patches.append(payload)
            server.update(payload)
            return {}
        def stop(_seconds):
            raise RuntimeError("controller interrupted")
        with patch.object(r, "list_check", lambda *_: armed), patch.object(r, "api", api), \
                patch.object(r.time, "sleep", stop), patch.object(r.signal, "signal", lambda *_: None):
            with self.assertRaises(RuntimeError):
                r.controller(ctx, "test-token")
        self.assertEqual(patches, [{"status": "completed", "conclusion": "failure"}])
        self.assertEqual(server["output"], core)

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
