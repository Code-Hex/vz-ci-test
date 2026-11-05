#!/usr/bin/env python3
"""Normal-reboot proof through a second job's sealed check-run credential."""
import base64
import hashlib
import recovery_reports
import recovery_bootargs
import recovery_bootplist
import recovery_nvram_panic
import recovery_panic_control
import recovery_arrival
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import selectors
import stat
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = "Code-Hex/vz-ci-test"
KERNEL_UUID = "87453B1D-A163-31FA-B33B-0FB4BE78E6E8"
API = "https://api.github.com/repos/Code-Hex/vz-ci-test"
CHECKS = API + "/check-runs"


def valid_context(ctx, system, machine, kernel_uuid=None):
    common = (ctx.get("actions") == "true" and ctx.get("repo") == REPO and
              ctx.get("ref") == "refs/heads/main" and ctx.get("event") == "workflow_dispatch" and
              ctx.get("runner_environment") == "github-hosted" and ctx.get("trigger", "reboot") in ("reboot", "reboot-quick", "panic-control", "panic-force-reset") and
              bool(re.fullmatch(r"[1-9][0-9]{0,19}", str(ctx.get("run_id", "")))) and
              bool(re.fullmatch(r"[1-9][0-9]{0,4}", str(ctx.get("attempt", "")))) and
              bool(re.fullmatch(r"[0-9a-f]{40}", str(ctx.get("sha", "")))) and
              ctx.get("debug_source") in ("nvram", "bootplist") and
              (ctx.get("debug_source") != "bootplist" or ctx.get("debug_boot") is True and ctx.get("trigger") == "reboot-quick") and
              ctx.get("after_debug_boot", "none") in ("none", "panic-nonce") and
              (ctx.get("after_debug_boot", "none") == "none" or ctx.get("debug_source") == "bootplist" and ctx.get("debug_boot") is True and ctx.get("trigger") == "reboot-quick") and
              type(ctx.get("debug_boot", False)) is bool and
              (not ctx.get("debug_boot", False) or ctx.get("trigger", "reboot") in ("reboot", "reboot-quick")))
    return bool(common and machine == "x86_64" and
                ((system == "Darwin" and str(kernel_uuid).upper() == KERNEL_UUID) or system == "Linux"))


def force_marker(ctx, nonce):
    run, attempt = ctx.get("run_id", ""), ctx.get("attempt", "")
    if (not re.fullmatch(r"[1-9][0-9]{0,19}", run) or not re.fullmatch(r"[1-9][0-9]{0,4}", attempt) or
            not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce)):
        raise ValueError("force reset marker invalid")
    return "vz-force-reset:" + run + ":" + attempt + ":" + nonce


def panic_mode(ctx):
    return ctx.get("trigger", "reboot") in ("panic-control", "panic-force-reset")


def panic_followup(ctx):
    return ctx.get("after_debug_boot", "none") == "panic-nonce"


def expected_debug_mask(ctx):
    return 0x102000 if panic_followup(ctx) else 0x2000


def report_required(ctx):
    return panic_mode(ctx) or panic_followup(ctx)


def binding(ctx):
    return ctx["run_id"] + "/" + ctx["attempt"] + "/" + ctx["sha"]


def select_check(checks, ctx):
    matches = [c for c in checks if c.get("name") == "Runner recovery " + ctx["run_id"] and
               c.get("external_id") == binding(ctx) and c.get("head_sha") == ctx["sha"] and
               c.get("app", {}).get("slug") == "github-actions" and c.get("app", {}).get("id") == 15368 and
               type(c.get("id")) is int and c["id"] > 0 and
               c.get("details_url") == "https://github.com/Code-Hex/vz-ci-test/runs/" + str(c["id"])]
    if len(matches) > 1:
        raise ValueError("duplicate matching check")
    return matches[0] if matches else None


def cleanup_identity(check, check_id, current):
    if not isinstance(check_id, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", check_id):
        return False
    external = check.get("external_id")
    if not isinstance(external, str):
        return False
    match = re.fullmatch(r"([1-9][0-9]{0,19})/([1-9][0-9]{0,4})/([0-9a-f]{40})", external)
    if not match or match.group(1) == current.get("run_id"):
        return False
    old = {"run_id": match.group(1), "attempt": match.group(2), "sha": match.group(3)}
    return (type(check.get("id")) is int and str(check["id"]) == check_id and
            select_check([check], old) is not None)


def cleanup_eligible(check, check_id, current):
    return cleanup_identity(check, check_id, current) and check.get("status") in {"queued", "in_progress", "waiting", "requested", "pending"}


def cleanup_old_check(ctx, token, check_id):
    if not re.fullmatch(r"[1-9][0-9]{0,19}", check_id):
        raise ValueError("invalid cleanup check identifier")
    check = api("GET", CHECKS + "/" + check_id, token)
    if not cleanup_identity(check, check_id, ctx):
        raise ValueError("cleanup check identity rejected")
    if cleanup_eligible(check, check_id, ctx):
        api("PATCH", CHECKS + "/" + check_id, token,
            {"status": "completed", "conclusion": "cancelled",
             "output": {"title": "Prior recovery attempt cancelled", "summary": "Superseded recovery attempt."}})
        status = "cancelled"
    elif check.get("status") == "completed":
        status = "already_completed"
    else:
        raise ValueError("cleanup check status unknown")
    print(json.dumps({"event": "cleanup_check", "id": int(check_id), "status": status}), flush=True)


def reboot_observed(before, after):
    return bool(before and after and before != after)


def mode_matches(data, pending, ctx):
    return (data.get("debug_source") in ("nvram", "bootplist") and data.get("debug_source") == ctx.get("debug_source") and
            data.get("after_debug_boot", "none") == ctx.get("after_debug_boot", "none") and
            data.get("trigger", "reboot") == ctx.get("trigger", "reboot") and
            type(data.get("debug_boot", False)) is bool and
            data.get("debug_boot", False) == ctx.get("debug_boot", False) and
            data.get("cert_fingerprint", "") == pending.get("cert_fingerprint", ""))


def armed_matches(data, pending, ctx):
    return (mode_matches(data, pending, ctx) and data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and
            data.get("phase") == "armed" and data.get("nonce") == pending["nonce"] and
            data.get("baseline_boot_uuid") == pending["baseline_boot_uuid"])


def sealed_matches(data, pending, ctx):
    return (mode_matches(data, pending, ctx) and data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and
            data.get("phase") == "sealed_token" and data.get("nonce") == pending["nonce"] and
            data.get("baseline_boot_uuid") == pending["baseline_boot_uuid"] and
            data.get("ciphertext") == pending["ciphertext"])


def debug_lineage_matches(data, pending, ctx):
    facts = data.get("debug_boot_facts")
    if not debug_boot_proven(facts, ctx["debug_source"], expected_debug_mask(ctx)):
        return False
    if not panic_followup(ctx):
        return facts.get("current_boot_uuid") == data.get("current_boot_uuid")
    boots = [pending["baseline_boot_uuid"], data.get("debug_boot_uuid"), data.get("current_boot_uuid")]
    if any(not isinstance(value, str) or not recovery_panic_control.UUID.fullmatch(value) for value in boots):
        return False
    if len({value.upper() for value in boots}) != 3 or facts.get("current_boot_uuid") != boots[1]:
        return False
    trigger = data.get("panic_trigger")
    scope = {"binding": binding(ctx), "nonce": pending["nonce"], "baseline": boots[0],
             "source_identity": debug_source_identity(), "debug_boot_uuid": boots[1]}
    return (isinstance(trigger, dict) and set(trigger) == {"scope", "helper_sha256", "helper_pid", "tracer_pid", "ready"} and
            trigger["scope"] == scope and trigger["ready"] is True and
            isinstance(trigger["helper_sha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", trigger["helper_sha256"])) and
            all(type(trigger[name]) is int and 0 < trigger[name] < 2**31 for name in ("helper_pid", "tracer_pid")))


def boot_proof_matches(data, pending, ctx):
    return (mode_matches(data, pending, ctx) and data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and
            data.get("phase") == "boot_observed" and data.get("nonce") == pending["nonce"] and
            data.get("baseline_boot_uuid") == pending["baseline_boot_uuid"] and
            reboot_observed(pending["baseline_boot_uuid"], data.get("current_boot_uuid")) and
            (not ctx.get("debug_boot", False) or debug_lineage_matches(data, pending, ctx)))


def debug_restored(facts, source):
    if source == "nvram":
        return facts.get("nvram_restored") is True
    expected = {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}
    return (source == "bootplist" and facts.get("bootplist_restored") is True and
            facts.get("bootplist_restore") == expected and
            isinstance(facts.get("bootplist_file_states"), dict) and
            set(facts["bootplist_file_states"]) == {"data", "preboot"} and
            all(value in ("original", "staged") for value in facts["bootplist_file_states"].values()))


def debug_boot_proven(facts, source, expected_mask=0x2000):
    return (isinstance(facts, dict) and type(facts.get("active_debug_mask")) is int and
            facts["active_debug_mask"] == expected_mask and facts.get("active_bootargs_status") == "observed_debug" and
            debug_restored(facts, source))


def panic_envelope_matches(data, ciphertext, pending, ctx):
    if not boot_proof_matches(data, pending, ctx):
        return False
    if panic_followup(ctx):
        capture = data.get("panic_capture")
        if (data.get("capture_state") != "fresh_fragment" or not isinstance(capture, dict) or
                capture.get("status") != "fresh_fragment" or capture.get("freshness") != "verified" or
                capture.get("completeness") != "unknown" or capture.get("encoding") not in ("raw", "packA")):
            return False
    elif data.get("capture_state") != "captured":
        return False
    if not isinstance(ciphertext, str) or len(ciphertext.encode()) > 58000:
        return False
    try:
        raw = base64.b64decode(ciphertext, validate=True)
    except (ValueError, TypeError):
        return False
    return bool(raw and hashlib.sha256(raw).hexdigest() == data.get("cipher_sha256"))


def openssl(*args, data=None, timeout=20):
    return subprocess.run(["/usr/bin/openssl", *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          check=True, timeout=timeout).stdout


def encrypt_token(public, token):
    if not isinstance(token, str) or not token or len(token.encode()) > 446:
        raise ValueError("job token length incompatible with RSA-4096 OAEP SHA-256")
    if len(public) > 4096 or b"-----BEGIN PUBLIC KEY-----" not in public:
        raise ValueError("invalid public key")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "public.pem"
        path.write_bytes(public)
        text = openssl("pkey", "-pubin", "-in", str(path), "-text", "-noout")
        if not re.search(rb"(?:RSA )?Public-Key:\s*\(4096 bit\)", text):
            raise ValueError("public key is not RSA-4096")
        return openssl("pkeyutl", "-encrypt", "-pubin", "-inkey", str(path),
                       "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                       "-pkeyopt", "rsa_mgf1_md:sha256", data=token.encode())


def decrypt_token(private, ciphertext):
    if len(ciphertext) != 512:
        raise ValueError("ciphertext length invalid")
    raw = openssl("pkeyutl", "-decrypt", "-inkey", str(private),
                  "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                  "-pkeyopt", "rsa_mgf1_md:sha256", data=ciphertext)
    token = raw.decode("utf-8")
    if not token or len(raw) > 446:
        raise ValueError("decrypted token invalid")
    return token


def command_output(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=5).strip()


def context_from_env():
    trigger = os.getenv("RECOVERY_TRIGGER", "reboot")
    return {"actions": os.getenv("GITHUB_ACTIONS", ""), "repo": os.getenv("GITHUB_REPOSITORY", ""),
            "ref": os.getenv("GITHUB_REF", ""), "event": os.getenv("GITHUB_EVENT_NAME", ""),
            "runner_environment": os.getenv("RUNNER_ENVIRONMENT", ""), "run_id": os.getenv("GITHUB_RUN_ID", ""),
            "attempt": os.getenv("GITHUB_RUN_ATTEMPT", ""), "sha": os.getenv("GITHUB_SHA", ""),
            "trigger": trigger, "debug_source": os.getenv("RECOVERY_DEBUG_SOURCE", "nvram"),
            "after_debug_boot": os.getenv("RECOVERY_AFTER_DEBUG_BOOT", "none"),
            "debug_boot": recovery_bootargs.requested(os.getenv("RECOVERY_DEBUG_BOOT", ""), trigger)}


def require_context(ctx, expected_system):
    system = command_output(["/usr/bin/uname", "-s"])
    machine = command_output(["/usr/bin/uname", "-m"])
    uuid = command_output(["/usr/sbin/sysctl", "-n", "kern.uuid"]) if system == "Darwin" else None
    if system != expected_system or not valid_context(ctx, system, machine, uuid):
        raise ValueError("runner context guard rejected")
    if system == "Darwin" and command_output(["/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"]) != "1":
        raise ValueError("runner VMM guard rejected")


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(method, url, token, payload=None, timeout=10):
    valid = (url == CHECKS or re.fullmatch(re.escape(CHECKS) + r"/[1-9][0-9]*", url) or
             re.fullmatch(re.escape(API) + r"/commits/[0-9a-f]{40}/check-runs\?filter=all&per_page=100", url))
    if not valid:
        raise ValueError("unexpected API endpoint")
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, method=method, data=data,
                                 headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                                          "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28",
                                          "User-Agent": "vz-recovery-smoke"})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as response:
        return json.load(response)


def list_check(ctx, token):
    result = api("GET", API + "/commits/" + ctx["sha"] + "/check-runs?filter=all&per_page=100", token)
    checks = result.get("check_runs", [])
    if result.get("total_count", 0) > len(checks):
        raise ValueError("check list incomplete")
    return select_check(checks, ctx)


def diagnostic_sysctls():
    result = {}
    try:
        value = command_output(["/usr/bin/fdesetup", "status"])
        result["filevault_status"] = {"FileVault is Off.": "Off", "FileVault is On.": "On"}.get(value, "unknown")
    except (OSError, subprocess.SubprocessError):
        result["filevault_status"] = "unknown"
    try:
        value = command_output(["/usr/sbin/sysctl", "-n", "machdep.misc.panic_restart_timeout"])
        result["panic_restart_timeout"] = int(value) if re.fullmatch(r"-?[0-9]+", value) else "unavailable"
    except (OSError, ValueError, subprocess.SubprocessError):
        result["panic_restart_timeout"] = "unavailable"
    try:
        args = command_output(["/usr/sbin/sysctl", "-n", "kern.bootargs"])
        result["bootargs_available"] = True
        result["debug_bootarg_present"] = bool(re.search(r"(?:^|\s)debug(?:=|\s|$)", args))
        result["panic_restart_bootarg_present"] = bool(re.search(r"(?:^|\s)panic_restart_timeout(?:=|\s|$)", args))
    except (OSError, subprocess.SubprocessError):
        result["bootargs_available"] = False
    return result


def checked_boot_argument_profile(value):
    if not isinstance(value, dict):
        raise ValueError("boot argument profile invalid")
    if value in ({"status": "unavailable"}, {"status": "invalid"}):
        return dict(value)
    if (set(value) != {"status", "debug_mask", "nondebug_token_count", "nondebug_sha256"} or
            value["status"] != "observed" or
            not (value["debug_mask"] is None or type(value["debug_mask"]) is int and 0 <= value["debug_mask"] <= 0xffffffff) or
            type(value["nondebug_token_count"]) is not int or not 0 <= value["nondebug_token_count"] <= 512 or
            not isinstance(value["nondebug_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["nondebug_sha256"])):
        raise ValueError("boot argument profile invalid")
    return dict(value)


def observe_boot_argument_profile():
    try:
        return recovery_bootargs.boot_argument_profile(recovery_bootargs.MacPlatform().active())
    except (OSError, subprocess.SubprocessError):
        return {"status": "unavailable"}
    except ValueError:
        return {"status": "invalid"}


def postboot_argument_profiles(directory, config, current):
    try:
        initial = checked_boot_argument_profile(config.get("initial_boot_argument_profile", {"status": "unavailable"}))
    except ValueError:
        initial = {"status": "invalid"}
    scope = {"marker": debug_boot_marker(config), "current_boot_uuid": current}
    path = directory / "boot-argument-observation.json"
    try:
        if path.exists():
            saved = json.loads(path.read_text())
            if not isinstance(saved, dict) or set(saved) != {"scope", "profile"} or saved["scope"] != scope:
                raise ValueError("boot argument observation identity mismatch")
            profile = checked_boot_argument_profile(saved["profile"])
        else:
            profile = checked_boot_argument_profile(observe_boot_argument_profile())
            private_write(path, json.dumps({"scope": scope, "profile": profile}).encode())
            sync_directory(directory)
    except (OSError, ValueError, subprocess.SubprocessError):
        profile = {"status": "invalid"}
    equal = None
    if initial["status"] == profile["status"] == "observed":
        equal = all(initial[key] == profile[key] for key in ("nondebug_token_count", "nondebug_sha256"))
    return {"initial": initial, "postboot": profile, "nondebug_equal": equal}


def root_dir(ctx):
    return Path("/var/root") / ("vz-ci-recovery-" + ctx["run_id"] + "-" + ctx["attempt"])


def boot_uuid():
    return command_output(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"])


def root_only():
    if os.geteuid() != 0:
        raise ValueError("root required")


def load_config(directory):
    root_only()
    if not re.fullmatch(r"/var/root/vz-ci-recovery-[1-9][0-9]{0,19}-[1-9][0-9]{0,4}", str(directory)):
        raise ValueError("invalid recovery directory")
    if directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise ValueError("invalid recovery permissions")
    config = json.loads((directory / "config.json").read_text())
    require_context(config["context"], "Darwin")
    if root_dir(config["context"]) != directory:
        raise ValueError("recovery identity mismatch")
    return config


def prepare_root(payload):
    root_only()
    ctx, token = payload["context"], payload["token"]
    require_context(ctx, "Darwin")
    if not token or len(token.encode()) > 446:
        raise ValueError("invalid job token")
    python = str(Path(sys.executable).resolve())
    if not Path(python).is_file() or not os.access(python, os.X_OK):
        raise ValueError("daemon Python executable unavailable")
    cert = payload.get("report_cert", "").encode()
    fingerprint = ""
    if report_required(ctx):
        fingerprint = recovery_reports.encrypt_bundle(cert, {"preflight": True}, b"synthetic")["cert_fingerprint"]
    directory = root_dir(ctx)
    directory.mkdir(mode=0o700)
    if fingerprint:
        private_write(directory / "report-cert.pem", cert)
    helper_kind = {"panic-force-reset": ("force_helper", "recovery-force-reset", "reboot-force-reset"),
                   "reboot-quick": ("quick_helper", "recovery-quick-reboot", "reboot-quick")}.get(ctx.get("trigger"))
    if helper_kind:
        key, basename, installed = helper_kind
        helper_path = payload.get(key, "")
        if not isinstance(helper_path, str) or not os.path.isabs(helper_path) or Path(helper_path).name != basename:
            raise ValueError("recovery helper path invalid")
        fd = os.open(helper_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("recovery helper must be a regular file")
            helper_data = stream.read(4 * 1024 * 1024 + 1)
        if not helper_data or len(helper_data) > 4 * 1024 * 1024:
            raise ValueError("recovery helper size invalid")
        helper = directory / installed
        private_write(helper, helper_data)
        os.chmod(helper, 0o700)
        helper_sha = hashlib.sha256(helper_data).hexdigest()
    else:
        helper_sha = ""
    nvram_helper_sha = ""
    nvram_source_sha = ""
    if ctx.get("debug_boot") and ctx.get("trigger") == "reboot-quick" and ctx["debug_source"] == "nvram":
        helper_path = payload.get("nvram_helper", "")
        nvram_source_sha = payload.get("nvram_source_sha256", "")
        if (not isinstance(helper_path, str) or not os.path.isabs(helper_path) or
                Path(helper_path).name != "recovery-nvram-backend" or
                not isinstance(nvram_source_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", nvram_source_sha)):
            raise ValueError("NVRAM helper metadata invalid")
        fd = os.open(helper_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("NVRAM helper must be a regular file")
            helper_data = stream.read(4 * 1024 * 1024 + 1)
        if not helper_data or len(helper_data) > 4 * 1024 * 1024:
            raise ValueError("NVRAM helper size invalid")
        private_write(directory / "nvram-backend", helper_data)
        os.chmod(directory / "nvram-backend", 0o700)
        nvram_helper_sha = hashlib.sha256(helper_data).hexdigest()
    private = directory / "key.pem"
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", timeout=90))
        stream.flush()
        os.fsync(stream.fileno())
    public = openssl("pkey", "-in", str(private), "-pubout").decode()
    nonce = secrets.token_hex(32)
    baseline = boot_uuid()
    if not baseline:
        raise ValueError("empty boot session")
    initial_boot_argument_profile = observe_boot_argument_profile() if panic_followup(ctx) else {"status": "unavailable"}
    if panic_followup(ctx):
        recovery_panic_control.build(directory, nonce, private_write, sync_directory)
        baseline_status, baseline_raw = recovery_nvram_panic.read_panic_info()
        marker = {"binding": binding(ctx), "nonce": nonce, "baseline": baseline, "source_identity": debug_source_identity()}
        private_write(directory / "panic-followup-baseline.json", json.dumps({"marker": marker, "boot_stage": "initial",
                      "status": baseline_status, "sha256": hashlib.sha256(baseline_raw).hexdigest() if baseline_raw is not None else None}).encode())
        sync_directory(directory)
    summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "public_key", "binding": binding(ctx),
                          "nonce": nonce, "baseline_boot_uuid": baseline, "public_key": public,
                          "trigger": ctx.get("trigger", "reboot"), "debug_boot": ctx.get("debug_boot", False), "debug_source": ctx["debug_source"], "after_debug_boot": ctx.get("after_debug_boot", "none"), "cert_fingerprint": fingerprint})
    check = api("POST", CHECKS, token, {"name": "Runner recovery " + ctx["run_id"], "head_sha": ctx["sha"],
                "external_id": binding(ctx), "status": "in_progress",
                "output": {"title": "Awaiting controller", "summary": summary}})
    if not isinstance(check.get("id"), int) or check["id"] <= 0:
        raise ValueError("invalid check identifier")
    config = {"context": ctx, "baseline": baseline, "check_id": check["id"], "nonce": nonce, "python": python, "cert_fingerprint": fingerprint, "helper_sha256": helper_sha,
              "debug_boot": ctx.get("debug_boot", False),
              "nvram_helper_sha256": nvram_helper_sha, "nvram_source_sha256": nvram_source_sha,
              "debug_source_identity": debug_source_identity() if ctx.get("debug_boot", False) else "",
              "arrival_api_ipv4": recovery_arrival.resolve_api()}
    config["initial_boot_argument_profile"] = initial_boot_argument_profile
    private_write(directory / "config.json", json.dumps(config).encode())
    private_write(directory / "recovery.py", Path(__file__).read_bytes())
    private_write(directory / "recovery_reports.py", Path(recovery_reports.__file__).read_bytes())
    private_write(directory / "recovery_bootargs.py", Path(recovery_bootargs.__file__).read_bytes())
    private_write(directory / "recovery_bootplist.py", Path(recovery_bootplist.__file__).read_bytes())
    private_write(directory / "recovery_nvram_panic.py", Path(recovery_nvram_panic.__file__).read_bytes())
    private_write(directory / "recovery_panic_control.py", Path(recovery_panic_control.__file__).read_bytes())
    private_write(directory / "panic-source-preflight.py", Path(__file__).with_name("panic-source-preflight.py").read_bytes())
    private_write(directory / "recovery_arrival.py", Path(recovery_arrival.__file__).read_bytes())
    private_write(directory / "arrival.sh", recovery_arrival.render(config, directory))
    sync_directory(directory)
    sync_directory(directory.parent)
    print(json.dumps({"event": "recovery_public_key_ready", "check_id": check["id"], "python": python,
                      "boot_uuid": baseline, "kernel_uuid": KERNEL_UUID, "hv_vmm_present": 1,
                      **diagnostic_sysctls()}), flush=True)


def verified_summary(check, config):
    ctx = config["context"]
    if select_check([check], ctx) is None or check.get("id") != config["check_id"]:
        raise ValueError("check identity mismatch")
    data = json.loads(check.get("output", {}).get("summary", "{}"))
    if data.get("protocol") != "vz-recovery-v1" or data.get("binding") != binding(ctx) or data.get("nonce") != config["nonce"] or data.get("baseline_boot_uuid") != config["baseline"] or not mode_matches(data, config, ctx):
        raise ValueError("check protocol mismatch")
    return data


def arm_root(payload):
    root_only()
    ctx, own_token = payload["context"], payload["token"]
    require_context(ctx, "Darwin")
    directory = root_dir(ctx)
    config = load_config(directory)
    if config["context"] != ctx or boot_uuid() != config["baseline"]:
        raise ValueError("boot or identity mismatch")
    deadline = time.monotonic() + 480
    token = None
    while time.monotonic() < deadline:
        check = api("GET", CHECKS + "/" + str(config["check_id"]), own_token)
        data = verified_summary(check, config)
        if data.get("phase") == "sealed_token":
            token = decrypt_token(directory / "key.pem", base64.b64decode(data["ciphertext"], validate=True))
            break
        if data.get("phase") != "public_key" or check.get("status") != "in_progress":
            raise ValueError("unexpected controller phase")
        time.sleep(2)
    if token is None:
        raise ValueError("controller token timeout")
    header = recovery_arrival.authorization_header(token)
    private_write(directory / "token", token.encode())
    private_write(directory / "arrival.headers", header)
    label = "com.vz.ci.recovery." + ctx["run_id"] + "." + ctx["attempt"]
    plist = Path("/Library/LaunchDaemons") / (label + ".plist")
    python = config["python"]
    if not Path(python).is_file() or not os.access(python, os.X_OK) or str(Path(python).resolve()) != python:
        raise ValueError("daemon Python executable changed")
    data = plistlib.dumps({"Label": label, "ProgramArguments": ["/usr/bin/env", "-i", "/bin/sh", str(directory / "arrival.sh")],
                           "RunAtLoad": True, "StandardOutPath": str(directory / "launchd.log"),
                           "StandardErrorPath": str(directory / "launchd.log"),
                           **({"StartInterval": 5} if config.get("debug_boot", False) else {})})
    fd = os.open(plist, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(directory)
    sync_directory(plist.parent)
    subprocess.run(["/bin/launchctl", "bootstrap", "system", str(plist)], check=True, timeout=15,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(json.dumps({"event": "recovery_daemon_installed", "check_id": config["check_id"], "python": python}), flush=True)


def verify_root(payload):
    root_only()
    ctx = payload["context"]
    require_context(ctx, "Darwin")
    directory = root_dir(ctx)
    config = load_config(directory)
    ready = json.loads((directory / "ready.json").read_text())
    if (config["context"] != ctx or ready.get("baseline") != config["baseline"] or
            ready.get("nonce") != config["nonce"] or ready.get("preboot_patch") is not True or
            boot_uuid() != config["baseline"]):
        raise ValueError("ready or boot mismatch")
    print(json.dumps({"ready": True, "preboot_patch": True, "check_id": config["check_id"],
                      "baseline_boot_uuid": config["baseline"], "nonce": config["nonce"]}), flush=True)


PANIC_SOURCE = "dtrace:::BEGIN { panic(); }"


def debug_boot_marker(config):
    return {"baseline": config["baseline"], "nonce": config["nonce"], "binding": binding(config["context"]),
            "source_identity": config.get("debug_source_identity", "")}


def debug_source_identity():
    return hashlib.sha256(Path(__file__).read_bytes() + b"\0" + Path(recovery_bootargs.__file__).read_bytes() + b"\0" + Path(recovery_bootplist.__file__).read_bytes() + b"\0" + Path(recovery_nvram_panic.__file__).read_bytes() + b"\0" + Path(recovery_panic_control.__file__).read_bytes() + b"\0" + Path(__file__).with_name("panic-source-preflight.py").read_bytes()).hexdigest()


DEBUG_EVENTS = ("request", "staged", "bootplist_inflight", "bootplist_staged", "native_inflight", "native_synced", "native_failed", "rollback_inflight", "rollback_cleanup", "intent", "returned", "uncertain", "aborted")
DEBUG_REASONS = ("stage_failure", "orphan_stage", "timeout", "interrupted", "exec_error", "rollback_failed", "intent_storage_error", "intent_ack_failure")


def read_debug_event(directory, config, event):
    record = json.loads((directory / ("debug-reboot-" + event + ".json")).read_text())
    expected = {"event": event, "binding": binding(config["context"]), "baseline": config["baseline"],
                "nonce": config["nonce"], "source_identity": config["debug_source_identity"],
                "actual_boot_uuid": config["baseline"]}
    if not isinstance(record, dict) or any(record.get(key) != value for key, value in expected.items()):
        raise ValueError("debug owner event identity mismatch")
    result = {"event": event, "actual_boot_uuid": record["actual_boot_uuid"], "source_identity": record["source_identity"]}
    for key in ("pid", "reboot_pid"):
        if type(record.get(key)) is int and 0 < record[key] < 2**31:
            result[key] = record[key]
    if type(record.get("returncode")) is int and -128 <= record["returncode"] <= 255:
        result["returncode"] = record["returncode"]
    if record.get("reason") in DEBUG_REASONS:
        result["reason"] = record["reason"]
    if record.get("nvram_before_rollback") in ("staged", "original", "partial", "unstaged"):
        result["nvram_before_rollback"] = record["nvram_before_rollback"]
    if event == "bootplist_staged":
        fact = record.get("bootplist_stage")
        if config["context"]["debug_source"] != "bootplist" or fact != {"data": "staged", "preboot": "staged", "metadata_preserved": True}:
            raise ValueError("boot plist stage evidence invalid")
        result["bootplist_stage"] = fact
    if event == "native_synced":
        fact = record.get("native_sync")
        if not valid_native_sync(fact, config):
            raise ValueError("native sync evidence invalid")
        result["native_sync"] = fact
    if event in ("native_failed", "rollback_cleanup"):
        fact = record.get("sync_result")
        if not valid_native_result(fact, cleanup=(event == "rollback_cleanup")):
            raise ValueError("native failure evidence invalid")
        result["sync_result"] = fact
    if isinstance(record.get("quick_return"), dict):
        returned = safe_quick_return(json.dumps(record["quick_return"]))
        if returned is not None:
            result["quick_return"] = returned
    return result


def debug_event(directory, config, event, current, **details):
    if event not in DEBUG_EVENTS or current != config["baseline"]:
        raise ValueError("debug event scope invalid")
    path = directory / ("debug-reboot-" + event + ".json")
    if not path.exists():
        record = {"event": event, "binding": binding(config["context"]), "baseline": config["baseline"],
                  "nonce": config["nonce"], "source_identity": config["debug_source_identity"],
                  "actual_boot_uuid": current, "pid": os.getpid(), **details}
        private_write(path, json.dumps(record).encode())
        sync_directory(directory)
    return read_debug_event(directory, config, event)


def debug_request_root(payload):
    root_only()
    ctx = payload["context"]
    require_context(ctx, "Darwin")
    directory = root_dir(ctx)
    config = load_config(directory)
    verify_root(payload)
    if (config["context"] != ctx or config.get("debug_boot") is not True or
            ctx.get("debug_boot") is not True or ctx.get("trigger") not in ("reboot", "reboot-quick") or
            config.get("debug_source_identity") != debug_source_identity()):
        raise ValueError("debug boot control not permitted")
    debug_event(directory, config, "request", config["baseline"])
    label = "com.vz.ci.recovery." + ctx["run_id"] + "." + ctx["attempt"]
    status = "uncertain"
    try:
        result = subprocess.run(["/bin/launchctl", "kickstart", "system/" + label], timeout=10,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            status = "submitted"
    except (OSError, subprocess.SubprocessError):
        pass
    print(json.dumps({"event": "debug_reboot_requested", "request_persisted": True, "kickstart_status": status}), flush=True)


def debug_reboot_child():
    try:
        child = subprocess.Popen(["/sbin/reboot"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return {"reason": "exec_error"}
    try:
        return {"returncode": child.wait(timeout=15), "reboot_pid": child.pid}
    except subprocess.TimeoutExpired:
        return {"reason": "timeout", "reboot_pid": child.pid}


class NativeSyncUncertain(Exception):
    pass


class NativeSyncFailure(ValueError):
    def __init__(self, fact):
        super().__init__("native sync failed")
        self.fact = fact


def native_failure_fact(raw, code):
    try:
        if len(raw) > 4096 or type(code) is not int or not -128 <= code <= 255:
            raise ValueError()
        rows = [json.loads(line) for line in raw.splitlines()]
        events = [row for row in rows if isinstance(row, dict) and row.get("event") == "sync"]
        if len(events) != 1:
            raise ValueError()
        event = events[0]
        if event.get("status") == "returned" and type(event.get("ioreturn")) is int and 0 <= event["ioreturn"] <= 0xffffffff:
            return {"status": "returned", "exit": code, "ioreturn": event["ioreturn"]}
        if code == 69 and event.get("status") in ("options_unavailable", "options_type_mismatch"):
            return {"status": event["status"], "exit": code}
    except (ValueError, UnicodeDecodeError):
        pass
    return {"status": "invalid"}


def valid_native_result(fact, cleanup=False):
    if not isinstance(fact, dict):
        return False
    if cleanup:
        if type(fact.get("sameboot_readback_original")) is not bool:
            return False
        fact = {key: value for key, value in fact.items() if key != "sameboot_readback_original"}
    status = fact.get("status")
    if status in ("invalid", "failed_or_uncertain"):
        return set(fact) == {"status"}
    if status in ("options_unavailable", "options_type_mismatch"):
        return set(fact) == {"status", "exit"} and type(fact["exit"]) is int and fact["exit"] == 69
    return (status == "returned" and set(fact) == {"status", "exit", "ioreturn"} and
            type(fact["exit"]) is int and -128 <= fact["exit"] <= 255 and
            type(fact["ioreturn"]) is int and 0 <= fact["ioreturn"] <= 0xffffffff)


def terminal_native_failure(fact):
    return (valid_native_result(fact) and
            ((fact['status'] == 'returned' and fact['exit'] == 70 and fact['ioreturn'] != 0) or
             (fact['status'] in ('options_unavailable', 'options_type_mismatch') and fact['exit'] == 69)))


def native_sync_fact(raw, code, before, after, binary_sha, source_sha):
    if (code != 0 or len(raw) > 4096 or before != {"boot_args": "staged", "canary": "staged"} or
            after != {"boot_args": "staged", "canary": "staged"} or
            not isinstance(binary_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", binary_sha) or
            not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", source_sha)):
        raise ValueError("native sync failed")
    try:
        rows = [json.loads(line) for line in raw.splitlines()]
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("native sync output invalid") from error
    events = [row for row in rows if isinstance(row, dict) and row.get("event") == "sync"]
    if (len(events) != 1 or events[0].get("status") != "returned" or
            type(events[0].get("ioreturn")) is not int or events[0]["ioreturn"] != 0):
        raise ValueError("native sync result invalid")
    return {"exit": 0, "ioreturn": 0, "before_key_states": dict(before), "after_key_states": dict(after), "binary_sha256": binary_sha,
            "source_sha256": source_sha, "prior_cli_sync": True}


def valid_native_sync(fact, config):
    return (isinstance(fact, dict) and set(fact) == {"exit", "ioreturn", "before_key_states", "after_key_states", "binary_sha256", "source_sha256", "prior_cli_sync"} and
            type(fact["exit"]) is int and fact["exit"] == 0 and type(fact["ioreturn"]) is int and fact["ioreturn"] == 0 and
            fact["before_key_states"] == {"boot_args": "staged", "canary": "staged"} and
            fact["after_key_states"] == {"boot_args": "staged", "canary": "staged"} and
            fact["binary_sha256"] == config.get("nvram_helper_sha256") and
            fact["source_sha256"] == config.get("nvram_source_sha256") and fact["prior_cli_sync"] is True and
            bool(re.fullmatch(r"[0-9a-f]{64}", str(fact["binary_sha256"]))) and
            bool(re.fullmatch(r"[0-9a-f]{64}", str(fact["source_sha256"]))))


def invoke_native_helper(directory, config):
    helper = directory / "nvram-backend"
    expected = config.get("nvram_helper_sha256", "")
    if (not helper.is_file() or helper.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}", str(expected)) or
            hashlib.sha256(helper.read_bytes()).hexdigest() != expected or boot_uuid() != config["baseline"]):
        raise ValueError("native helper identity mismatch")
    try:
        child = subprocess.Popen([str(helper), "force-sync"], env=helper_env(config), stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, bufsize=0)
    except OSError:
        raise
    except BaseException as error:
        raise NativeSyncUncertain() from error
    try:
        return finish_native_helper(child, config)
    except NativeSyncUncertain:
        raise
    except BaseException as error:
        raise NativeSyncUncertain() from error


def finish_native_helper(child, config):
    selector = None
    output = bytearray()
    deadline = time.monotonic() + 10
    failed = False
    try:
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not selector.select(max(0, left)):
                failed = True
                break
            chunk = os.read(child.stdout.fileno(), min(4097 - len(output), 4096))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 4096:
                failed = True
                break
        if failed:
            try:
                child.kill()
            except OSError:
                pass
        try:
            code = child.wait(timeout=max(0.01, deadline - time.monotonic())) if not failed else child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            failed = True
            try:
                child.kill()
            except OSError:
                pass
            code = None
    except BaseException as error:
        raise NativeSyncUncertain() from error
    finally:
        if selector is not None:
            selector.close()
        if child.poll() is None:
            try:
                child.kill()
            except OSError:
                pass
            while child.poll() is None:
                try:
                    child.wait()
                except KeyboardInterrupt:
                    continue
        child.stdout.close()
    if failed:
        raise NativeSyncUncertain()
    try:
        if boot_uuid() != config["baseline"]:
            raise NativeSyncUncertain()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise NativeSyncUncertain() from error
    return bytes(output), code


def native_force_sync(directory, config, platform):
    helper = directory / "nvram-backend"
    expected = config.get("nvram_helper_sha256", "")
    if (not helper.is_file() or helper.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}", str(expected)) or
            hashlib.sha256(helper.read_bytes()).hexdigest() != expected or boot_uuid() != config["baseline"]):
        raise ValueError("native helper identity mismatch")
    original = recovery_bootargs.parse_nvram((directory / "debug-boot-original.plist").read_bytes())
    staged = recovery_bootargs.parse_nvram((directory / "debug-boot-staged.plist").read_bytes())
    expected_states = {"boot_args": "staged", "canary": "staged"}
    before = recovery_bootargs.key_states(original, staged, platform.read())[1]
    if before != expected_states:
        raise ValueError("native sync precondition changed")
    output, code = invoke_native_helper(directory, config)
    try:
        observed = native_failure_fact(output, code)
        if terminal_native_failure(observed):
            raise NativeSyncFailure(observed)
        if observed != {"status": "returned", "exit": 0, "ioreturn": 0}:
            raise NativeSyncUncertain()
        states = recovery_bootargs.key_states(original, staged, platform.read())[1]
        return native_sync_fact(output, code, before, states, expected, config.get("nvram_source_sha256", ""))
    except (NativeSyncFailure, NativeSyncUncertain):
        raise
    except BaseException as error:
        raise NativeSyncUncertain() from error


def rollback_native_sync(directory, config, platform):
    original = recovery_bootargs.parse_nvram((directory / "debug-boot-original.plist").read_bytes())
    if boot_uuid() != config["baseline"] or platform.read() != original:
        return {"status": "failed_or_uncertain", "sameboot_readback_original": False}
    try:
        raw, code = invoke_native_helper(directory, config)
    except NativeSyncUncertain:
        raise
    except (OSError, ValueError, subprocess.SubprocessError):
        fact = {"status": "failed_or_uncertain"}
    else:
        try:
            fact = native_failure_fact(raw, code)
            if fact != {"status": "returned", "exit": 0, "ioreturn": 0} and not terminal_native_failure(fact):
                raise NativeSyncUncertain()
        except NativeSyncUncertain:
            raise
        except BaseException as error:
            raise NativeSyncUncertain() from error
    try:
        fact["sameboot_readback_original"] = boot_uuid() == config["baseline"] and platform.read() == original
    except (OSError, ValueError, subprocess.SubprocessError):
        fact["sameboot_readback_original"] = False
    return fact


def debug_owner(directory, config, current):
    if (current != config["baseline"] or config.get("debug_boot") is not True or
            config["context"].get("trigger") not in ("reboot", "reboot-quick") or config.get("debug_source_identity") != debug_source_identity()):
        raise ValueError("debug owner context mismatch")
    read_debug_event(directory, config, "request")
    for event in ("aborted", "intent", "rollback_cleanup"):
        if (directory / ("debug-reboot-" + event + ".json")).exists():
            read_debug_event(directory, config, event)
            return
    cleanup_inflight = directory / "debug-reboot-rollback_inflight.json"
    if cleanup_inflight.exists():
        read_debug_event(directory, config, "rollback_inflight")
        if not (directory / "debug-reboot-rollback_cleanup.json").exists():
            return
    inflight = directory / "debug-reboot-native_inflight.json"
    if inflight.exists():
        try:
            read_debug_event(directory, config, "native_inflight")
            settled = False
            if (directory / "debug-reboot-native_synced.json").exists():
                read_debug_event(directory, config, "native_synced")
                settled = True
            if (directory / "debug-reboot-native_failed.json").exists():
                failure = read_debug_event(directory, config, "native_failed")
                if not terminal_native_failure(failure.get("sync_result")) or settled:
                    return
                settled = True
            if not settled:
                return
        except (OSError, ValueError, KeyError):
            return
    source = config["context"]["debug_source"]
    if source == "bootplist" and (directory / "debug-reboot-bootplist_inflight.json").exists():
        read_debug_event(directory, config, "bootplist_inflight")
        return
    platform = recovery_bootargs.MacPlatform()
    marker = debug_boot_marker(config)
    reason = "orphan_stage" if (directory / "debug-boot-stage.json").exists() else "stage_failure"
    try:
        if reason == "orphan_stage":
            raise ValueError("prior preintent stage interrupted")
        if not recovery_bootargs.csr_allowed():
            raise ValueError("kernel debugging not permitted")
        if source == "bootplist":
            debug_event(directory, config, "bootplist_inflight", current)
            fact = recovery_bootplist.stage(directory, marker, private_write, sync_directory, debug_mask=expected_debug_mask(config["context"]))
            debug_event(directory, config, "bootplist_staged", current, bootplist_stage=fact)
        else:
            recovery_bootargs.stage(directory, marker, platform, private_write, sync_directory)
        debug_event(directory, config, "staged", current)
        if source == "nvram" and config["context"].get("trigger") == "reboot-quick":
            debug_event(directory, config, "native_inflight", current)
            try:
                fact = native_force_sync(directory, config, platform)
            except NativeSyncUncertain:
                return
            except NativeSyncFailure as error:
                if not terminal_native_failure(error.fact):
                    return
                debug_event(directory, config, "native_failed", current, sync_result=error.fact)
                raise
            except (OSError, ValueError, subprocess.SubprocessError):
                debug_event(directory, config, "native_failed", current, sync_result={"status": "failed_or_uncertain"})
                raise
            debug_event(directory, config, "native_synced", current, native_sync=fact)
        prepared = quick_prepare(directory, config) if config["context"].get("trigger") == "reboot-quick" else None
        debug_event(directory, config, "intent", current)
    except recovery_bootplist.WriteUncertain:
        return
    except BaseException:
        if (directory / "debug-reboot-intent.json").exists():
            debug_event(directory, config, "uncertain", current, reason="intent_storage_error")
            return
        try:
            if source == "bootplist":
                if (directory / "bootplist-manifest.json").exists():
                    recovery_bootplist.rollback(directory, marker, private_write, sync_directory, current_boot_uuid=boot_uuid())
                debug_event(directory, config, "aborted", current, reason=reason)
                return
            state = recovery_bootargs.rollback(directory, marker, platform, private_write, sync_directory)
            if config["context"].get("trigger") == "reboot-quick" and (directory / "debug-boot-original.plist").exists():
                debug_event(directory, config, "rollback_inflight", current)
                cleanup = rollback_native_sync(directory, config, platform)
                debug_event(directory, config, "rollback_cleanup", current, sync_result=cleanup)
                print(json.dumps({"event": "rollback_cleanup", **cleanup}), flush=True)
            debug_event(directory, config, "aborted", current, reason=reason, nvram_before_rollback=state)
        except (NativeSyncUncertain, recovery_bootplist.WriteUncertain):
            return
        except BaseException:
            debug_event(directory, config, "aborted", current, reason="rollback_failed")
        return
    if prepared is not None:
        try:
            prepared = quick_intent_ack(directory, config, prepared)
        except BaseException:
            debug_event(directory, config, "uncertain", current, reason="intent_ack_failure")
            return
    try:
        if prepared is None:
            result = debug_reboot_child()
        else:
            result = quick_reboot_child(directory, config,
                on_uncertain=lambda reason: debug_event(directory, config, "uncertain", current, reason=reason))
    except BaseException:
        result = {"reason": "interrupted"}
    event = "returned" if "returncode" in result else "uncertain"
    debug_event(directory, config, event, current, **result)
    if result.get("quick_return") is not None:
        quick_report_return(directory, config, prepared, result["quick_return"])


def panic_preflight_root(payload):
    root_only()
    ctx = payload["context"]
    require_context(ctx, "Darwin")
    if ctx.get("trigger") != "panic-control":
        raise ValueError("panic trigger not selected")
    directory = root_dir(ctx)
    config = load_config(directory)
    verify_root(payload)
    if config["context"] != ctx or (directory / "trigger.json").exists():
        raise ValueError("panic already triggered or identity mismatch")
    baseline = recovery_reports.inventory()
    private_write(directory / "report-baseline.json", json.dumps(baseline, separators=(",", ":")).encode())
    sync_directory(directory)
    before = command_output(["/usr/sbin/sysctl", "-n", "machdep.misc.panic_restart_timeout"])
    subprocess.run(["/usr/sbin/sysctl", "-w", "machdep.misc.panic_restart_timeout=5"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    after = command_output(["/usr/sbin/sysctl", "-n", "machdep.misc.panic_restart_timeout"])
    if after != "5":
        raise ValueError("panic restart timeout readback mismatch")
    subprocess.run(["/usr/sbin/dtrace", "-w", "-e", "-n", PANIC_SOURCE], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    prepared = {"source_sha256": hashlib.sha256(PANIC_SOURCE.encode()).hexdigest(), "old_timeout": before,
                "new_timeout": after, "boot_uuid": config["baseline"]}
    private_write(directory / "panic-preflight.json", json.dumps(prepared).encode())
    sync_directory(directory)
    print(json.dumps({"event": "panic_preflight_complete", "preboot_patch": True,
                      "source_sha256": prepared["source_sha256"], "timeout_readback": 5,
                      "dtrace_compile_exit": 0}), flush=True)


def panic_execute_root(payload):
    root_only()
    ctx = payload["context"]
    require_context(ctx, "Darwin")
    if ctx.get("trigger") != "panic-control":
        raise ValueError("panic trigger not selected")
    directory = root_dir(ctx)
    config = load_config(directory)
    verify_root(payload)
    prepared = json.loads((directory / "panic-preflight.json").read_text())
    if (config["context"] != ctx or prepared.get("boot_uuid") != config["baseline"] or
            prepared.get("source_sha256") != hashlib.sha256(PANIC_SOURCE.encode()).hexdigest() or
            command_output(["/usr/sbin/sysctl", "-n", "machdep.misc.panic_restart_timeout"]) != "5"):
        raise ValueError("panic preflight changed")
    private_write(directory / "trigger.json", json.dumps(prepared).encode())
    sync_directory(directory)
    os.sync()
    subprocess.run(["/usr/sbin/dtrace", "-w", "-n", PANIC_SOURCE], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    raise RuntimeError("panic action unexpectedly returned")


def helper_env(config):
    ctx = config["context"]
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GITHUB_ACTIONS": ctx["actions"],
            "GITHUB_EVENT_NAME": ctx["event"], "GITHUB_REPOSITORY": ctx["repo"], "GITHUB_REF": ctx["ref"],
            "RUNNER_ENVIRONMENT": ctx["runner_environment"], "GITHUB_RUN_ID": ctx["run_id"],
            "GITHUB_RUN_ATTEMPT": ctx["attempt"], "GITHUB_SHA": ctx["sha"], "RECOVERY_TRIGGER": ctx["trigger"],
            "VZ_RECOVERY_NONCE": config["nonce"], "VZ_RECOVERY_BOOT_UUID": config["baseline"]}


def helper_checked(directory, config, name):
    helper = directory / name
    if not helper.is_file() or helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest() != config.get("helper_sha256"):
        raise ValueError("recovery helper identity mismatch")
    return helper


def force_preflight_root(payload):
    root_only()
    ctx = payload["context"]
    require_context(ctx, "Darwin")
    if ctx.get("trigger") != "panic-force-reset":
        raise ValueError("force trigger not selected")
    directory = root_dir(ctx)
    config = load_config(directory)
    verify_root(payload)
    if config["context"] != ctx or (directory / "trigger.json").exists():
        raise ValueError("force trigger identity or once guard")
    helper = helper_checked(directory, config, "reboot-force-reset")
    baseline = recovery_reports.inventory()
    private_write(directory / "report-baseline.json", json.dumps(baseline, separators=(",", ":")).encode())
    sync_directory(directory)
    result = subprocess.run([str(helper), "preflight"], env=helper_env(config), capture_output=True,
                            text=True, timeout=10)
    if result.returncode != 0:
        failure = safe_force_preflight_error(result.stderr)
        if failure is not None:
            print(json.dumps(failure), flush=True)
        raise RuntimeError("force helper preflight failed")
    fact = json.loads(result.stdout)
    if (fact.get("event") != "force_reset_preflight" or fact.get("symbol_available") is not True or
            fact.get("flags") != 0x2c00 or fact.get("entitlement_verified") is not False):
        raise ValueError("force helper preflight invalid")
    marker = force_marker(ctx, config["nonce"])
    prepared = {"trigger": "panic-force-reset", "helper_sha256": config["helper_sha256"],
                "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(), "boot_uuid": config["baseline"]}
    private_write(directory / "force-preflight.json", json.dumps(prepared).encode())
    sync_directory(directory)
    print(json.dumps({"event": "force_preflight_complete", "preboot_patch": True,
                      "symbol_available": True, "entitlement_verified": False, "flags": 0x2c00}), flush=True)


def force_execute_root(payload):
    root_only()
    ctx = payload["context"]
    require_context(ctx, "Darwin")
    if ctx.get("trigger") != "panic-force-reset":
        raise ValueError("force trigger not selected")
    directory = root_dir(ctx)
    config = load_config(directory)
    verify_root(payload)
    helper = helper_checked(directory, config, "reboot-force-reset")
    prepared = json.loads((directory / "force-preflight.json").read_text())
    marker = force_marker(ctx, config["nonce"])
    if (config["context"] != ctx or prepared.get("trigger") != "panic-force-reset" or
            prepared.get("boot_uuid") != config["baseline"] or prepared.get("helper_sha256") != config["helper_sha256"] or
            prepared.get("marker_sha256") != hashlib.sha256(marker.encode()).hexdigest()):
        raise ValueError("force preflight changed")
    private_write(directory / "trigger.json", json.dumps(prepared).encode())
    sync_directory(directory)
    os.sync()
    result = subprocess.run([str(helper), "execute"], env=helper_env(config), capture_output=True,
                            text=True, timeout=30)
    for line in result.stderr.splitlines():
        try:
            fact = json.loads(line)
        except ValueError:
            continue
        if (isinstance(fact, dict) and fact.get("event") == "force_reset_unexpected_return" and
                type(fact.get("result")) is int and -1 <= fact["result"] <= 0 and
                type(fact.get("errno")) is int and 0 <= fact["errno"] <= 4095):
            print(json.dumps({"event": "force_reset_unexpected_return", "result": fact["result"],
                              "errno": fact["errno"]}), flush=True)
    raise RuntimeError("force reset unexpectedly returned")


def quick_execute_root(payload):
    root_only()
    ctx = payload["context"]
    require_context(ctx, "Darwin")
    if ctx.get("trigger") != "reboot-quick" or ctx.get("debug_boot", False):
        raise ValueError("quick reboot trigger rejected")
    directory = root_dir(ctx)
    config = load_config(directory)
    verify_root(payload)
    if config["context"] != ctx or config.get("debug_boot", False) or boot_uuid() != config["baseline"]:
        raise ValueError("quick reboot identity mismatch")
    prepared = quick_prepare(directory, config)
    result = quick_reboot_child(directory, config)
    if result.get("quick_return") is not None:
        quick_report_return(directory, config, prepared, result["quick_return"])
    raise RuntimeError("quick reboot helper unexpectedly returned")


def quick_prepare(directory, config):
    ctx = config["context"]
    if boot_uuid() != config["baseline"]:
        raise ValueError("quick preparation boot mismatch")
    helper = helper_checked(directory, config, "reboot-quick")
    marker = {"trigger": "reboot-quick", "binding": binding(ctx), "nonce": config["nonce"],
              "boot_uuid": config["baseline"], "helper_sha256": config["helper_sha256"], "flags": 0x400,
              "debug_boot": ctx.get("debug_boot", False)}
    private_write(directory / "quick-trigger.json", json.dumps(marker).encode())
    sync_directory(directory)
    os.sync()
    preflight = subprocess.run([str(helper), "preflight"], env=helper_env(config), capture_output=True, text=True, check=True, timeout=10)
    fact = json.loads(preflight.stdout)
    if (not isinstance(fact, dict) or fact.get("event") != "quick_reboot_preflight" or
            type(fact.get("flags")) is not int or fact["flags"] != 0x400 or fact.get("permission_verified") is not False):
        raise ValueError("quick reboot preflight invalid")
    token = (directory / "token").read_text()
    url = CHECKS + "/" + str(config["check_id"])
    check = api("GET", url, token)
    prepared = verified_summary(check, config)
    if check.get("status") != "in_progress" or prepared.get("phase") != "armed":
        raise ValueError("quick reboot armed checkpoint absent")
    prepared = {**prepared, "phase": "quick_prepared", "quick_flags": 0x400,
                "helper_sha256": config["helper_sha256"], "permission_verified": False}
    output = {"title": "Quick reboot prepared", "summary": json.dumps(prepared), "text": ""}
    api("PATCH", url, token, {"status": "in_progress", "output": output})
    check = api("GET", url, token)
    verified_summary(check, config)
    if (check.get("status") != "in_progress" or check.get("conclusion") is not None or
            check.get("output", {}).get("summary") != output["summary"] or check["output"].get("title") != output["title"] or
            boot_uuid() != config["baseline"]):
        raise ValueError("quick reboot checkpoint acknowledgement mismatch")
    helper_checked(directory, config, "reboot-quick")
    return prepared


def quick_intent_ack(directory, config, prepared):
    if (config.get("debug_boot") is not True or config["context"].get("trigger") != "reboot-quick" or
            prepared.get("phase") != "quick_prepared" or not mode_matches(prepared, config, config["context"])):
        raise ValueError("quick intent context mismatch")
    source = config["context"]["debug_source"]
    evidence = "bootplist_staged" if source == "bootplist" else "native_synced"
    intent = {**prepared, "phase": "quick_intent",
              "owner_events": [read_debug_event(directory, config, event) for event in ("staged", evidence, "intent")]}
    if source == "nvram" and not valid_native_sync(intent["owner_events"][1].get("native_sync"), config):
        raise ValueError("native sync evidence mismatch")
    output = {"title": "Quick reboot intent durable", "summary": json.dumps(intent), "text": ""}
    url = CHECKS + "/" + str(config["check_id"])
    token = (directory / "token").read_text()
    api("PATCH", url, token, {"status": "in_progress", "output": output})
    check = api("GET", url, token)
    verified_summary(check, config)
    actual = check.get("output", {})
    if (check.get("status") != "in_progress" or check.get("conclusion") is not None or
            actual.get("title") != output["title"] or actual.get("summary") != output["summary"] or
            actual.get("text") not in (None, "") or boot_uuid() != config["baseline"]):
        raise ValueError("quick intent acknowledgement mismatch")
    return intent


def quick_reboot_child(directory, config, on_uncertain=None):
    helper = helper_checked(directory, config, "reboot-quick")
    try:
        child = subprocess.Popen([str(helper), "execute"], env=helper_env(config), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError:
        return {"reason": "exec_error"}
    timeout, reported = 30, False
    while True:
        try:
            stdout, _stderr = child.communicate(timeout=timeout)
            break
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            if not reported:
                reported = True
                try:
                    if on_uncertain is not None:
                        on_uncertain("timeout" if isinstance(error, subprocess.TimeoutExpired) else "interrupted")
                except BaseException:
                    pass
            timeout = None
    return {"returncode": child.returncode, "reboot_pid": child.pid, "quick_return": safe_quick_return(stdout)}


def quick_report_return(directory, config, prepared, returned):
    print(json.dumps(returned), flush=True)
    failure = {**prepared, "phase": "quick_failed", "quick_return": returned}
    try:
        api("PATCH", CHECKS + "/" + str(config["check_id"]), (directory / "token").read_text(),
            {"status": "completed", "conclusion": "failure",
             "output": {"title": "Quick reboot syscall returned", "summary": json.dumps(failure)}})
    except (OSError, ValueError, urllib.error.URLError):
        pass


def panic_capture(directory, config, current, deadline):
    baseline = json.loads((directory / "report-baseline.json").read_text())
    marker = json.loads((directory / "trigger.json").read_text())
    trigger = config["context"].get("trigger", "reboot")
    expected_marker = None
    if trigger == "panic-control":
        valid = (marker.get("new_timeout") == "5" and marker.get("source_sha256") == hashlib.sha256(PANIC_SOURCE.encode()).hexdigest())
    elif trigger == "panic-force-reset":
        expected_marker = force_marker(config["context"], config["nonce"])
        valid = (marker.get("trigger") == trigger and marker.get("helper_sha256") == config.get("helper_sha256") and
                 marker.get("marker_sha256") == hashlib.sha256(expected_marker.encode()).hexdigest())
    else:
        valid = False
    if marker.get("boot_uuid") != config["baseline"] or not valid:
        raise ValueError("trigger marker invalid")
    capture_deadline = deadline - 45
    while time.monotonic() < capture_deadline:
        try:
            capture = recovery_reports.select_stable(recovery_reports.ROOTS, baseline, trigger=trigger, marker=expected_marker)
            metadata = {"binding": binding(config["context"]), "nonce": config["nonce"],
                        "baseline_boot_uuid": config["baseline"], "current_boot_uuid": current,
                        "kernel_uuid": KERNEL_UUID, "report_sha256": capture["sha256"]}
            envelope = recovery_reports.encrypt_bundle((directory / "report-cert.pem").read_bytes(), metadata, capture["data"])
            if envelope["cert_fingerprint"] != config["cert_fingerprint"]:
                raise ValueError("certificate mismatch")
            return envelope
        except (recovery_reports.NoReport, recovery_reports.UnstableReport):
            time.sleep(min(2, max(0, capture_deadline - time.monotonic())))
    raise recovery_reports.NoReport("report capture timeout")


def publish_debug_core(directory, config, current, facts, token):
    scope = {"marker": debug_boot_marker(config), "current_boot_uuid": current}
    path = directory / "debug-boot-core.json"
    if path.exists():
        saved = json.loads(path.read_text())
        if not isinstance(saved, dict) or saved.get("scope") != scope or not isinstance(saved.get("facts"), dict):
            raise ValueError("boot core identity mismatch")
        facts = saved["facts"]
    else:
        private_write(path, json.dumps({"scope": scope, "facts": facts}).encode())
        sync_directory(directory)
    if facts.get("current_boot_uuid") != current:
        raise ValueError("boot core observation mismatch")
    ctx = config["context"]
    summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "boot_core", "binding": binding(ctx),
                          "nonce": config["nonce"], "baseline_boot_uuid": config["baseline"], "current_boot_uuid": current,
                          "trigger": ctx.get("trigger", "reboot"), "cert_fingerprint": config.get("cert_fingerprint", ""),
                          "debug_boot": True, "debug_source": ctx["debug_source"], "after_debug_boot": ctx.get("after_debug_boot", "none"), "debug_boot_facts": facts})
    output = {"title": "Boot core recovered", "summary": summary, "text": ""}
    url = CHECKS + "/" + str(config["check_id"])
    api("PATCH", url, token, {"status": "in_progress", "output": output})
    check = api("GET", url, token)
    verified_summary(check, config)
    actual = check.get("output", {})
    if (check.get("status") != "in_progress" or check.get("conclusion") is not None or
            actual.get("title") != output["title"] or actual.get("summary") != summary or actual.get("text") not in (None, "")):
        raise ValueError("boot core acknowledgement mismatch")
    return facts


def followup_summary(config, phase, current, saved, **details):
    ctx = config["context"]
    return {"protocol": "vz-recovery-v1", "phase": phase, "binding": binding(ctx), "nonce": config["nonce"],
            "baseline_boot_uuid": config["baseline"], "current_boot_uuid": current,
            "trigger": ctx["trigger"], "debug_boot": True, "debug_source": ctx["debug_source"],
            "after_debug_boot": ctx["after_debug_boot"], "cert_fingerprint": config["cert_fingerprint"],
            "debug_boot_uuid": saved["scope"]["debug_boot_uuid"], "debug_boot_facts": saved["facts"], **details}


def publish_followup(directory, config, token, summary, title):
    output = {"title": title, "summary": json.dumps(summary), "text": ""}
    if len(json.dumps(output).encode()) > 58000:
        raise ValueError("followup output oversized")
    url = CHECKS + "/" + str(config["check_id"])
    api("PATCH", url, token, {"status": "in_progress", "output": output})
    check = api("GET", url, token)
    verified_summary(check, config)
    if check.get("status") != "in_progress" or check.get("conclusion") is not None or check.get("output") is None:
        raise ValueError("followup acknowledgement state mismatch")
    actual = check["output"]
    if actual.get("title") != title or actual.get("summary") != output["summary"] or actual.get("text") not in (None, ""):
        raise ValueError("followup acknowledgement content mismatch")


def read_followup_debug(directory, config):
    saved = json.loads((directory / "panic-followup-debug.json").read_text())
    if not isinstance(saved, dict) or set(saved) != {"scope", "facts"}:
        raise ValueError("followup record invalid")
    scope = saved["scope"]
    recovery_panic_control.validate_scope(scope)
    expected = {**debug_boot_marker(config), "debug_boot_uuid": scope["debug_boot_uuid"]}
    if (scope != expected or config["debug_source_identity"] != debug_source_identity() or
            not debug_boot_proven(saved["facts"], "bootplist", expected_debug_mask(config["context"])) or saved["facts"].get("current_boot_uuid") != scope["debug_boot_uuid"]):
        raise ValueError("followup debug proof invalid")
    return saved


def followup_start(directory, config, current, facts, token):
    if config["debug_source_identity"] != debug_source_identity():
        raise ValueError("followup source identity mismatch")
    scope = {**debug_boot_marker(config), "debug_boot_uuid": current}
    recovery_panic_control.validate_scope(scope)
    if not debug_boot_proven(facts, "bootplist", expected_debug_mask(config["context"])) or facts.get("current_boot_uuid") != current:
        raise ValueError("followup requires a restored debug boot")
    saved = {"scope": scope, "facts": facts}
    private_write(directory / "panic-followup-debug.json", json.dumps(saved).encode())
    sync_directory(directory)
    try:
        prepared = recovery_panic_control.prepare(directory, config["nonce"], private_write, sync_directory)
        publish_followup(directory, config, token, followup_summary(config, "panic_prepared", current, saved, prepared=prepared),
                         "Nonce panic control prepared")
        def on_ready(trigger):
            if trigger.get("scope") != scope or trigger.get("helper_sha256") != prepared["helper_sha256"] or trigger.get("ready") is not True:
                raise ValueError("panic trigger identity mismatch")
            private_write(directory / "panic-followup-trigger.json", json.dumps(trigger).encode())
            sync_directory(directory)
            publish_followup(directory, config, token,
                             followup_summary(config, "panic_intent", current, saved, panic_trigger=trigger, prepared=prepared),
                             "Nonce panic intent durable")
            return boot_uuid() == current
        returned = recovery_panic_control.fire(directory, scope, prepared, private_write, sync_directory, on_ready, boot_uuid)
        failure = {"status": "returned", "result": returned}
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, urllib.error.URLError) as error:
        failure = {"status": "failed", "kind": type(error).__name__}
    private_write(directory / "panic-followup-returned.json", json.dumps({"scope": scope, **failure}).encode())
    sync_directory(directory)
    names = tuple(label + "." + channel for label in ("build", "sign", "listing", "trace", "panic-compile", "tracer") for channel in ("stdout", "stderr")) + ("prepare-failure.json", "timeout-ps.stdout", "timeout-ps.stderr", "timeout-sample.stdout", "timeout-sample.stderr", "timeout-diagnostic.json")
    failure["files"] = {name: {"exists": (directory / "panic-control" / name).exists(),
                              "bytes": (directory / "panic-control" / name).stat().st_size if (directory / "panic-control" / name).exists() else None}
                        for name in names}
    failure["prepared"] = (directory / "panic-control" / "prepared.json").exists()
    failure["fire_intent"] = (directory / "panic-control" / "intent.json").exists()
    failure["release_attempt"] = (directory / "panic-control" / "release-attempt.json").exists()
    summary = followup_summary(config, "panic_returned", current, saved, panic_control=failure)
    output = {"title": "Nonce panic control returned", "summary": json.dumps(summary)}
    fragments = {}
    budget = 32768
    for name in names:
        path = directory / "panic-control" / name
        if path.exists() and budget:
            with path.open("rb") as stream:
                fragment = stream.read(budget)
            budget -= len(fragment)
            if fragment:
                fragments[name] = base64.b64encode(fragment).decode()
    if fragments:
        try:
            envelope = recovery_reports.encrypt_bundle((directory / "report-cert.pem").read_bytes(),
                        {"kind": "panic_control_failure", "scope": scope}, json.dumps(fragments).encode())
            if envelope["cert_fingerprint"] != config["cert_fingerprint"]:
                raise ValueError("failure envelope certificate mismatch")
            summary["failure_cipher_sha256"] = envelope["cipher_sha256"]
            output.update(summary=json.dumps(summary), text=envelope["ciphertext"])
        except (OSError, ValueError, subprocess.SubprocessError):
            summary["failure_encryption"] = "unavailable"
            output["summary"] = json.dumps(summary)
    complete_recovery(directory, config, current, token, output, False, time.monotonic() + 60)


def followup_finish(directory, config, current, saved, token):
    scope = saved["scope"]
    boots = [scope["baseline"], scope["debug_boot_uuid"], current]
    if any(not recovery_panic_control.UUID.fullmatch(value) for value in boots) or len({value.upper() for value in boots}) != 3:
        raise ValueError("followup capture boot invalid")
    trigger = json.loads((directory / "panic-followup-trigger.json").read_text())
    intent = json.loads((directory / "panic-control" / "intent.json").read_text())
    release = json.loads((directory / "panic-control" / "release-attempt.json").read_text())
    if trigger != release or trigger.get("scope") != scope or intent.get("scope") != scope:
        raise ValueError("followup release evidence invalid")
    recovery_panic_control.validate_prepared(directory, config["nonce"], intent.get("prepared"))
    if trigger.get("helper_sha256") != intent["prepared"]["helper_sha256"]:
        raise ValueError("followup helper mismatch")
    observation = directory / "panic-followup-observation.json"
    if observation.exists():
        capture = json.loads(observation.read_text())
        if capture.get("scope") != scope or capture.get("current_boot_uuid") != current:
            raise ValueError("followup capture identity mismatch")
        raw = (directory / "panic-followup-raw").read_bytes() if capture["has_raw"] else None
        if raw is not None and hashlib.sha256(raw).hexdigest() != capture["sha256"]:
            raise ValueError("followup raw digest mismatch")
    else:
        status, raw = recovery_nvram_panic.read_panic_info()
        capture = {"scope": scope, "current_boot_uuid": current, "status": status,
                   "sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None, "has_raw": raw is not None}
        if raw is not None:
            private_write(directory / "panic-followup-raw", raw)
        private_write(observation, json.dumps(capture).encode())
        sync_directory(directory)
    classification = recovery_nvram_panic.classify(raw, config["nonce"]) if raw is not None else {
        "status": "unavailable", "freshness": "unverified", "completeness": "unknown", "encoding": None}
    envelope = None
    if raw:
        metadata = {"binding": binding(config["context"]), "nonce": config["nonce"], "kernel_uuid": KERNEL_UUID,
                    "baseline_boot_uuid": config["baseline"], "debug_boot_uuid": scope["debug_boot_uuid"],
                    "current_boot_uuid": current, "source_identity": config["debug_source_identity"], "classification": classification}
        envelope = recovery_reports.encrypt_bundle((directory / "report-cert.pem").read_bytes(), metadata, raw)
        if envelope["cert_fingerprint"] != config["cert_fingerprint"]:
            raise ValueError("followup certificate mismatch")
    summary = followup_summary(config, "boot_observed", current, saved, panic_trigger=trigger,
                              panic_capture=classification, panic_getter_status=capture["status"],
                              capture_state="fresh_fragment" if envelope and classification["freshness"] == "verified" else "encrypted_unvalidated" if envelope else "unavailable",
                              cipher_sha256=envelope["cipher_sha256"] if envelope else "")
    pending = {"nonce": config["nonce"], "baseline_boot_uuid": config["baseline"], "cert_fingerprint": config["cert_fingerprint"]}
    successful = bool(envelope and panic_envelope_matches(summary, envelope["ciphertext"], pending, config["context"]))
    output = {"title": "Fresh nonce panic fragment recovered" if successful else "Nonce panic fragment unavailable",
              "summary": json.dumps(summary), "text": envelope["ciphertext"] if envelope else ""}
    complete_recovery(directory, config, current, token, output, successful, time.monotonic() + 180)


def complete_recovery(directory, config, current, token, output, successful, deadline):
    payload = {"status": "completed", "conclusion": "success" if successful else "failure", "output": output}
    while time.monotonic() < deadline:
        try:
            api("PATCH", CHECKS + "/" + str(config["check_id"]), token, payload,
                timeout=min(10, max(0.1, deadline - time.monotonic())))
            private_write(directory / "completed.json", json.dumps({"boot_uuid": current}).encode())
            (directory / "token").unlink()
            (directory / "arrival.headers").unlink(missing_ok=True)
            (directory / "key.pem").unlink()
            ctx = config["context"]
            plist = Path("/Library/LaunchDaemons") / ("com.vz.ci.recovery." + ctx["run_id"] + "." + ctx["attempt"] + ".plist")
            plist.unlink(missing_ok=True)
            sync_directory(directory)
            sync_directory(plist.parent)
            return
        except urllib.error.HTTPError as error:
            if error.code in (401, 403, 404):
                private_write(directory / "failed.json", json.dumps({"event": "check_update_failed", "status": error.code}).encode())
                return
        except (OSError, ValueError):
            pass
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    private_write(directory / "failed.json", b'{"event":"check_update_timeout"}')



def collect(directory):
    config = load_config(directory)
    if (directory / "completed.json").exists():
        return
    current = boot_uuid()
    if panic_followup(config["context"]) and (directory / "panic-followup-debug.json").exists():
        saved = read_followup_debug(directory, config)
        if current == saved["scope"]["debug_boot_uuid"]:
            return
        followup_finish(directory, config, current, saved, (directory / "token").read_text())
        return
    debug_facts = {}
    argument_profiles = None
    if reboot_observed(config["baseline"], current) and panic_followup(config["context"]):
        argument_profiles = postboot_argument_profiles(directory, config, current)
    if reboot_observed(config["baseline"], current) and config.get("debug_boot", False):
        try:
            if config["context"]["debug_source"] == "bootplist":
                debug_facts = recovery_bootplist.finish(directory, debug_boot_marker(config), private_write, sync_directory,
                                                        current_boot_uuid=current)
            else:
                debug_facts = recovery_bootargs.finish(directory, debug_boot_marker(config), recovery_bootargs.MacPlatform(), private_write, sync_directory,
                                                       current_boot_uuid=current, inventory=False)
        except (OSError, ValueError, subprocess.SubprocessError, recovery_bootplist.WriteUncertain):
            debug_facts = {"active_debug_mask": None, "active_bootargs_status": "unavailable", "current_boot_uuid": current}
            if config["context"]["debug_source"] == "bootplist":
                debug_facts.update({"bootplist_restored": False, "bootplist_restore": {},
                                    "bootplist_file_states": {"data": "unavailable", "preboot": "unavailable"}})
            else:
                debug_facts.update({"nvram_restored": False, "nvram_before_restore": "unavailable",
                                    "nvram_key_states": {"boot_args": "unavailable", "canary": "unavailable"},
                                    "debugger_count": None, "debugger_inventory_status": "unavailable",
                                    "network_inventory_status": "unavailable", "virtio_network_classes": [],
                                    "nic_inventory_status": "unsupported", "kernel_debug_state": {}})
        if argument_profiles is not None:
            debug_facts["boot_argument_profiles"] = argument_profiles
        debug_facts["owner_events"] = []
        for event in DEBUG_EVENTS:
            if (directory / ("debug-reboot-" + event + ".json")).exists():
                try:
                    debug_facts["owner_events"].append(read_debug_event(directory, config, event))
                except (OSError, ValueError):
                    debug_facts["owner_events"].append({"event": event, "status": "invalid"})
    elif config.get("debug_boot", False) and (directory / "debug-reboot-request.json").exists():
        debug_owner(directory, config, current)
        return
    token = (directory / "token").read_text()
    if not reboot_observed(config["baseline"], current):
        if not (directory / "ready.json").exists():
            summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "armed", "binding": binding(config["context"]),
                                  "nonce": config["nonce"], "baseline_boot_uuid": config["baseline"],
                                  "trigger": config["context"].get("trigger", "reboot"),
                                  "debug_boot": config.get("debug_boot", False), "debug_source": config["context"]["debug_source"], "after_debug_boot": config["context"].get("after_debug_boot", "none"),
                                  "cert_fingerprint": config.get("cert_fingerprint", "")})
            api("PATCH", CHECKS + "/" + str(config["check_id"]), token,
                {"output": {"title": "Recovery daemon ready", "summary": summary}})
            private_write(directory / "ready.json", json.dumps({"baseline": config["baseline"], "nonce": config["nonce"],
                                                                 "preboot_patch": True, "ready": True}).encode())
            sync_directory(directory)
        return
    ready = json.loads((directory / "ready.json").read_text())
    if ready.get("preboot_patch") is not True or ready.get("baseline") != config["baseline"] or ready.get("nonce") != config["nonce"]:
        raise ValueError("preboot confirmation missing")
    deadline = time.monotonic() + 180
    if config.get("debug_boot", False):
        try:
            debug_facts = dict(publish_debug_core(directory, config, current, debug_facts, token))
        except (OSError, ValueError, urllib.error.URLError):
            return
        if panic_followup(config["context"]):
            followup_start(directory, config, current, debug_facts, token)
            return
        if debug_restored(debug_facts, config["context"]["debug_source"]):
            try:
                optional = recovery_bootargs.observe_once(directory, debug_boot_marker(config), recovery_bootargs.MacPlatform(),
                                                          private_write, sync_directory, current_boot_uuid=current)
            except (OSError, ValueError, subprocess.SubprocessError):
                optional = {"optional_inventory_status": "uncertain"}
            debug_facts.update(optional)
        else:
            debug_facts["optional_inventory_status"] = "skipped_restore_failure"
    envelope = None
    capture_state = "boot_only"
    if panic_mode(config["context"]):
        try:
            envelope = panic_capture(directory, config, current, deadline)
            capture_state = "captured"
        except recovery_reports.NoReport:
            capture_state = "missing"
        except (OSError, ValueError, subprocess.SubprocessError):
            capture_state = "invalid"
    summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": binding(config["context"]),
                          "nonce": config["nonce"], "baseline_boot_uuid": config["baseline"], "current_boot_uuid": current,
                          "trigger": config["context"].get("trigger", "reboot"), "cert_fingerprint": config.get("cert_fingerprint", ""),
                          "debug_boot": config.get("debug_boot", False), "debug_source": config["context"]["debug_source"], "after_debug_boot": config["context"].get("after_debug_boot", "none"), "debug_boot_facts": debug_facts,
                          "capture_state": capture_state,
                          "cipher_sha256": envelope["cipher_sha256"] if envelope else "",
                          "note": "Boot UUID changed; no stopped-CPU GPR proof."})
    successful = config["context"].get("trigger", "reboot") in ("reboot", "reboot-quick") or capture_state == "captured"
    if config.get("debug_boot", False):
        successful = successful and debug_boot_proven(debug_facts, config["context"]["debug_source"], expected_debug_mask(config["context"]))
    output = {"title": "Recovery observed" if successful else "Panic report unavailable", "summary": summary}
    if envelope:
        output["text"] = envelope["ciphertext"]
    if len(json.dumps(output).encode()) > 58000:
        successful = False
        output = {"title": "Panic report unavailable", "summary": json.dumps({"protocol": "vz-recovery-v1",
                  "phase": "boot_observed", "binding": binding(config["context"]), "nonce": config["nonce"],
                  "baseline_boot_uuid": config["baseline"], "current_boot_uuid": current,
                  "trigger": config["context"].get("trigger", "reboot"), "cert_fingerprint": config.get("cert_fingerprint", ""),
                  "debug_boot": config.get("debug_boot", False), "debug_source": config["context"]["debug_source"], "after_debug_boot": config["context"].get("after_debug_boot", "none"),
                  "capture_state": "oversized"})}
    complete_recovery(directory, config, current, token, output, successful, deadline)


def root_error_kind(stderr):
    allowed = {"OSError", "FileNotFoundError", "PermissionError", "FileExistsError", "ValueError",
               "RuntimeError", "KeyError", "SubprocessError", "CalledProcessError", "TimeoutExpired",
               "URLError", "HTTPError", "JSONDecodeError", "UnicodeDecodeError"}
    for line in reversed(stderr.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("event") == "recovery_error":
            kind = value.get("kind")
            return kind if isinstance(kind, str) and kind in allowed else "unknown"
    return "unknown"


def safe_force_preflight_error(output):
    allowed = {"force_reset_guard_failed", "force_reset_symbol_unavailable"}
    for line in reversed(output.splitlines()):
        try:
            fact = json.loads(line)
        except ValueError:
            continue
        if isinstance(fact, dict) and isinstance(fact.get("event"), str) and fact["event"] in allowed:
            return {"event": fact["event"]}
    return None


def safe_force_return(stdout):
    for line in reversed(stdout.splitlines()):
        try:
            fact = json.loads(line)
        except ValueError:
            continue
        if (isinstance(fact, dict) and fact.get("event") == "force_reset_unexpected_return" and
                type(fact.get("result")) is int and -1 <= fact["result"] <= 0 and
                type(fact.get("errno")) is int and 0 <= fact["errno"] <= 4095):
            return {"event": "force_reset_unexpected_return", "result": fact["result"], "errno": fact["errno"]}
    return None


def safe_quick_return(stdout):
    for line in reversed(stdout.splitlines()):
        try:
            fact = json.loads(line)
        except ValueError:
            continue
        if (isinstance(fact, dict) and fact.get("event") == "quick_reboot_unexpected_return" and
                type(fact.get("result")) is int and -1 <= fact["result"] <= 0 and
                type(fact.get("errno")) is int and 0 <= fact["errno"] <= 4095):
            return {"event": "quick_reboot_unexpected_return", "result": fact["result"], "errno": fact["errno"]}
    return None


def sudo_call(operation, payload, timeout=40):
    proc = subprocess.run(["/usr/bin/sudo", "-n", sys.executable, str(Path(__file__).resolve()), operation],
                          input=json.dumps(payload), text=True, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        if operation == "force-execute-root":
            fact = safe_force_return(proc.stdout)
            if fact is not None:
                print(json.dumps(fact), flush=True)
        elif operation == "force-preflight-root":
            fact = safe_force_preflight_error(proc.stdout)
            if fact is not None:
                print(json.dumps(fact), flush=True)
        elif operation == "quick-execute-root":
            fact = safe_quick_return(proc.stdout)
            if fact is not None:
                print(json.dumps(fact), flush=True)
        print(json.dumps({"event": "root_operation_failed", "operation": operation,
                          "returncode": proc.returncode, "root_error_kind": root_error_kind(proc.stderr)}), flush=True)
        raise RuntimeError("root operation failed")
    return proc.stdout


def controller(ctx, token):
    deadline = time.monotonic() + (1080 if panic_followup(ctx) else 600)
    check_id = None
    pending = None
    sealed = False
    proof = False

    def interrupted(_signum, _frame):
        raise SystemExit(143)

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        while time.monotonic() < deadline:
            try:
                check = list_check(ctx, token)
                if check:
                    if check_id is not None and check_id != check["id"]:
                        raise ValueError("check identity changed")
                    check_id = check["id"]
                    data = json.loads(check.get("output", {}).get("summary", "{}"))
                    if check.get("status") == "completed":
                        matches = pending is not None and boot_proof_matches(data, pending, ctx)
                        if matches and report_required(ctx):
                            matches = panic_envelope_matches(data, check.get("output", {}).get("text", ""), pending, ctx)
                        if matches and check.get("conclusion") == "success":
                            print(json.dumps({"event": "controller_boot_proof", "check_id": check_id}), flush=True)
                            proof = True
                            return
                        raise ValueError("check completed without boot proof")
                    if data.get("phase") == "public_key" and data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and data.get("trigger", "reboot") == ctx.get("trigger", "reboot") and type(data.get("debug_boot", False)) is bool and data.get("debug_boot", False) == ctx.get("debug_boot", False) and data.get("debug_source") == ctx["debug_source"] and data.get("after_debug_boot", "none") == ctx.get("after_debug_boot", "none"):
                        nonce, baseline, public = data.get("nonce", ""), data.get("baseline_boot_uuid", ""), data.get("public_key", "")
                        if not re.fullmatch(r"[0-9a-f]{64}", nonce) or not re.fullmatch(r"[0-9A-Fa-f-]{36}", baseline):
                            raise ValueError("nonce or baseline invalid")
                        fingerprint = data.get("cert_fingerprint", "")
                        if report_required(ctx) and not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                            raise ValueError("certificate fingerprint invalid")
                        if not report_required(ctx) and fingerprint:
                            raise ValueError("unexpected certificate fingerprint")
                        if pending is None:
                            ciphertext = encrypt_token(public.encode(), token)
                            pending = {"nonce": nonce, "baseline_boot_uuid": baseline, "public_key": public,
                                       "ciphertext": base64.b64encode(ciphertext).decode(), "cert_fingerprint": fingerprint}
                        if (nonce, baseline, public, fingerprint) != (pending["nonce"], pending["baseline_boot_uuid"], pending["public_key"], pending["cert_fingerprint"]):
                            raise ValueError("public key metadata changed")
                        sealed_summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "sealed_token", "binding": binding(ctx),
                                                     "nonce": nonce, "baseline_boot_uuid": baseline, "ciphertext": pending["ciphertext"],
                                                     "trigger": ctx.get("trigger", "reboot"), "debug_boot": ctx.get("debug_boot", False), "debug_source": ctx["debug_source"], "after_debug_boot": ctx.get("after_debug_boot", "none"),
                                                     "cert_fingerprint": fingerprint})
                        api("PATCH", CHECKS + "/" + str(check_id), token,
                            {"output": {"title": "Controller credential sealed", "summary": sealed_summary}})
                        sealed = True
                        print(json.dumps({"event": "controller_token_sealed", "check_id": check_id}), flush=True)
                    elif pending is not None and (sealed_matches(data, pending, ctx) or armed_matches(data, pending, ctx)):
                        if not sealed:
                            print(json.dumps({"event": "controller_token_sealed_recovered", "check_id": check_id}), flush=True)
                        sealed = True
            except (OSError, urllib.error.URLError, subprocess.SubprocessError):
                pass
            time.sleep(min(3, max(0, deadline - time.monotonic())))
        raise RuntimeError("controller timed out")
    finally:
        signal.signal(signal.SIGTERM, previous)
        if not proof:
            if check_id is not None:
                try:
                    current = api("GET", CHECKS + "/" + str(check_id), token, timeout=5)
                    if select_check([current], ctx) is not None and current.get("status") != "completed":
                        payload = {"status": "completed", "conclusion": "failure"}
                        if not ctx.get("debug_boot", False) and ctx.get("trigger") != "reboot-quick":
                            payload["output"] = {"title": "Recovery not observed",
                                                 "summary": "Controller stopped before recovery proof; this does not prove a reboot or kernel failure."}
                        api("PATCH", CHECKS + "/" + str(check_id), token,
                            payload, timeout=5)
                except (OSError, urllib.error.URLError, ValueError):
                    pass


def main():
    if len(sys.argv) < 2:
        raise ValueError("usage: reboot-recovery.py prepare|arm|trigger|reboot|controller|cleanup")
    op = sys.argv[1]
    if op in ("prepare", "arm", "reboot", "trigger", "controller", "cleanup") and len(sys.argv) == 2:
        ctx = context_from_env()
        require_context(ctx, "Linux" if op in ("controller", "cleanup") else "Darwin")
        token = os.environ.pop("GITHUB_TOKEN", "") if op not in ("reboot", "trigger") else ""
        if op not in ("reboot", "trigger") and not token:
            raise ValueError("GITHUB_TOKEN missing")
        if op == "cleanup":
            cleanup_old_check(ctx, token, os.environ.get("RECOVERY_CLEANUP_CHECK_ID", ""))
            return
        if op == "controller":
            cleanup_id = os.environ.get("RECOVERY_CLEANUP_CHECK_ID", "")
            if cleanup_id:
                cleanup_old_check(ctx, token, cleanup_id)
            controller(ctx, token)
        elif op == "prepare":
            print(sudo_call("prepare-root", {"context": ctx, "token": token,
                            "report_cert": os.environ.pop("RECOVERY_REPORT_CERT", ""),
                            "force_helper": os.environ.pop("RECOVERY_FORCE_HELPER", ""),
                            "quick_helper": os.environ.pop("RECOVERY_QUICK_HELPER", ""),
                            "nvram_helper": os.environ.pop("RECOVERY_NVRAM_HELPER", ""),
                            "nvram_source_sha256": hashlib.sha256(Path("probes/nvram_backend.c").read_bytes()).hexdigest()
                            if ctx.get("debug_boot") and ctx.get("trigger") == "reboot-quick" and ctx["debug_source"] == "nvram" else ""}, timeout=120), end="", flush=True)
        elif op == "arm":
            print(sudo_call("arm-root", {"context": ctx, "token": token}, timeout=510), end="", flush=True)
            deadline = time.monotonic() + 20
            while True:
                try:
                    print(sudo_call("verify-root", {"context": ctx}), end="", flush=True)
                    break
                except RuntimeError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(1)
        elif op == "trigger" and ctx.get("trigger") == "panic-control":
            print(sudo_call("panic-preflight-root", {"context": ctx}, timeout=70), end="", flush=True)
            print(sudo_call("panic-execute-root", {"context": ctx}, timeout=45), end="", flush=True)
        elif op == "trigger" and ctx.get("trigger") == "panic-force-reset":
            print(sudo_call("force-preflight-root", {"context": ctx}, timeout=70), end="", flush=True)
            print(sudo_call("force-execute-root", {"context": ctx}, timeout=45), end="", flush=True)
        elif op == "trigger" and ctx.get("trigger") == "reboot-quick":
            if ctx.get("debug_boot", False):
                print(sudo_call("verify-root", {"context": ctx}), end="", flush=True)
                print(sudo_call("debug-request-root", {"context": ctx}), end="", flush=True)
                time.sleep(90)
            else:
                print(sudo_call("quick-execute-root", {"context": ctx}, timeout=90), end="", flush=True)
        else:
            if ctx.get("trigger", "reboot") != "reboot":
                raise ValueError("wrong trigger operation")
            print(sudo_call("verify-root", {"context": ctx}), end="", flush=True)
            if ctx.get("debug_boot", False):
                print(sudo_call("debug-request-root", {"context": ctx}), end="", flush=True)
                time.sleep(90)
                return
            os.sync()
            subprocess.run(["/usr/bin/sudo", "-n", "/sbin/reboot"], check=True, timeout=15)
    elif op in ("prepare-root", "arm-root", "verify-root", "panic-preflight-root", "panic-execute-root", "force-preflight-root", "force-execute-root", "debug-request-root", "quick-execute-root") and len(sys.argv) == 2:
        {"prepare-root": prepare_root, "arm-root": arm_root, "verify-root": verify_root, "panic-preflight-root": panic_preflight_root, "panic-execute-root": panic_execute_root,
         "force-preflight-root": force_preflight_root, "force-execute-root": force_execute_root,
         "debug-request-root": debug_request_root, "quick-execute-root": quick_execute_root}[op](json.load(sys.stdin))
    elif op == "collect" and len(sys.argv) == 3:
        collect(Path(sys.argv[2]))
    else:
        raise ValueError("invalid operation")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError, urllib.error.URLError) as error:
        print(json.dumps({"event": "recovery_error", "kind": type(error).__name__}), file=sys.stderr, flush=True)
        sys.exit(1)
