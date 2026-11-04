#!/usr/bin/env python3
"""Normal-reboot proof through a second job's sealed check-run credential."""
import base64
import hashlib
import recovery_reports
import recovery_bootargs
import recovery_arrival
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
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
              ctx.get("runner_environment") == "github-hosted" and ctx.get("trigger", "reboot") in ("reboot", "panic-control", "panic-force-reset") and
              bool(re.fullmatch(r"[1-9][0-9]{0,19}", str(ctx.get("run_id", "")))) and
              bool(re.fullmatch(r"[1-9][0-9]{0,4}", str(ctx.get("attempt", "")))) and
              bool(re.fullmatch(r"[0-9a-f]{40}", str(ctx.get("sha", "")))) and
              type(ctx.get("debug_boot", False)) is bool and
              (not ctx.get("debug_boot", False) or ctx.get("trigger", "reboot") == "reboot"))
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
    return (data.get("trigger", "reboot") == ctx.get("trigger", "reboot") and
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


def boot_proof_matches(data, pending, ctx):
    return (mode_matches(data, pending, ctx) and data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and
            data.get("phase") == "boot_observed" and data.get("nonce") == pending["nonce"] and
            data.get("baseline_boot_uuid") == pending["baseline_boot_uuid"] and
            reboot_observed(pending["baseline_boot_uuid"], data.get("current_boot_uuid")) and
            (not ctx.get("debug_boot", False) or
             debug_boot_proven(data.get("debug_boot_facts")) and
             data["debug_boot_facts"].get("current_boot_uuid") == data.get("current_boot_uuid")))


def debug_boot_proven(facts):
    return (isinstance(facts, dict) and type(facts.get("active_debug_mask")) is int and
            facts["active_debug_mask"] == 0x2000 and facts.get("active_bootargs_status") == "observed_debug" and
            facts.get("nvram_restored") is True)


def panic_envelope_matches(data, ciphertext, pending, ctx):
    if not boot_proof_matches(data, pending, ctx) or data.get("capture_state") != "captured":
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
            "trigger": trigger, "debug_boot": recovery_bootargs.requested(os.getenv("RECOVERY_DEBUG_BOOT", ""), trigger)}


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
    if panic_mode(ctx):
        fingerprint = recovery_reports.encrypt_bundle(cert, {"preflight": True}, b"synthetic")["cert_fingerprint"]
    directory = root_dir(ctx)
    directory.mkdir(mode=0o700)
    if fingerprint:
        private_write(directory / "report-cert.pem", cert)
    if ctx.get("trigger") == "panic-force-reset":
        helper_path = payload.get("force_helper", "")
        if not isinstance(helper_path, str) or not os.path.isabs(helper_path) or Path(helper_path).name != "recovery-force-reset":
            raise ValueError("force helper path invalid")
        fd = os.open(helper_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("force helper must be a regular file")
            helper_data = stream.read(4 * 1024 * 1024 + 1)
        if not helper_data or len(helper_data) > 4 * 1024 * 1024:
            raise ValueError("force helper size invalid")
        helper = directory / "reboot-force-reset"
        private_write(helper, helper_data)
        os.chmod(helper, 0o700)
        helper_sha = hashlib.sha256(helper_data).hexdigest()
    else:
        helper_sha = ""
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
    summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "public_key", "binding": binding(ctx),
                          "nonce": nonce, "baseline_boot_uuid": baseline, "public_key": public,
                          "trigger": ctx.get("trigger", "reboot"), "debug_boot": ctx.get("debug_boot", False), "cert_fingerprint": fingerprint})
    check = api("POST", CHECKS, token, {"name": "Runner recovery " + ctx["run_id"], "head_sha": ctx["sha"],
                "external_id": binding(ctx), "status": "in_progress",
                "output": {"title": "Awaiting controller", "summary": summary}})
    if not isinstance(check.get("id"), int) or check["id"] <= 0:
        raise ValueError("invalid check identifier")
    config = {"context": ctx, "baseline": baseline, "check_id": check["id"], "nonce": nonce, "python": python, "cert_fingerprint": fingerprint, "helper_sha256": helper_sha,
              "debug_boot": ctx.get("debug_boot", False),
              "debug_source_identity": debug_source_identity() if ctx.get("debug_boot", False) else "",
              "arrival_api_ipv4": recovery_arrival.resolve_api()}
    private_write(directory / "config.json", json.dumps(config).encode())
    private_write(directory / "recovery.py", Path(__file__).read_bytes())
    private_write(directory / "recovery_reports.py", Path(recovery_reports.__file__).read_bytes())
    private_write(directory / "recovery_bootargs.py", Path(recovery_bootargs.__file__).read_bytes())
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
    return hashlib.sha256(Path(__file__).read_bytes() + b"\0" + Path(recovery_bootargs.__file__).read_bytes()).hexdigest()


DEBUG_EVENTS = ("request", "staged", "intent", "returned", "uncertain", "aborted")
DEBUG_REASONS = ("stage_failure", "orphan_stage", "timeout", "interrupted", "exec_error", "rollback_failed", "intent_storage_error")


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
    if record.get("nvram_before_rollback") in ("staged", "original", "unstaged"):
        result["nvram_before_rollback"] = record["nvram_before_rollback"]
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
            ctx.get("debug_boot") is not True or ctx.get("trigger") != "reboot" or
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


def debug_owner(directory, config, current):
    if (current != config["baseline"] or config.get("debug_boot") is not True or
            config["context"].get("trigger") != "reboot" or config.get("debug_source_identity") != debug_source_identity()):
        raise ValueError("debug owner context mismatch")
    read_debug_event(directory, config, "request")
    for event in ("aborted", "intent"):
        if (directory / ("debug-reboot-" + event + ".json")).exists():
            read_debug_event(directory, config, event)
            return
    platform = recovery_bootargs.MacPlatform()
    marker = debug_boot_marker(config)
    reason = "orphan_stage" if (directory / "debug-boot-stage.json").exists() else "stage_failure"
    try:
        if reason == "orphan_stage":
            raise ValueError("prior preintent stage interrupted")
        if not recovery_bootargs.csr_allowed():
            raise ValueError("kernel debugging not permitted")
        recovery_bootargs.stage(directory, marker, platform, private_write, sync_directory)
        debug_event(directory, config, "staged", current)
        debug_event(directory, config, "intent", current)
    except BaseException:
        if (directory / "debug-reboot-intent.json").exists():
            debug_event(directory, config, "uncertain", current, reason="intent_storage_error")
            return
        try:
            state = recovery_bootargs.rollback(directory, marker, platform, private_write, sync_directory)
            debug_event(directory, config, "aborted", current, reason=reason, nvram_before_rollback=state)
        except BaseException:
            debug_event(directory, config, "aborted", current, reason="rollback_failed")
        return
    try:
        result = debug_reboot_child()
    except BaseException:
        result = {"reason": "interrupted"}
    event = "returned" if "returncode" in result else "uncertain"
    debug_event(directory, config, event, current, **result)


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


def force_helper_env(config):
    ctx = config["context"]
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GITHUB_ACTIONS": ctx["actions"],
            "GITHUB_EVENT_NAME": ctx["event"], "GITHUB_REPOSITORY": ctx["repo"], "GITHUB_REF": ctx["ref"],
            "RUNNER_ENVIRONMENT": ctx["runner_environment"], "GITHUB_RUN_ID": ctx["run_id"],
            "GITHUB_RUN_ATTEMPT": ctx["attempt"], "GITHUB_SHA": ctx["sha"], "RECOVERY_TRIGGER": ctx["trigger"],
            "VZ_RECOVERY_NONCE": config["nonce"], "VZ_RECOVERY_BOOT_UUID": config["baseline"]}


def force_helper_checked(directory, config):
    helper = directory / "reboot-force-reset"
    if not helper.is_file() or helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest() != config.get("helper_sha256"):
        raise ValueError("force helper identity mismatch")
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
    helper = force_helper_checked(directory, config)
    baseline = recovery_reports.inventory()
    private_write(directory / "report-baseline.json", json.dumps(baseline, separators=(",", ":")).encode())
    sync_directory(directory)
    result = subprocess.run([str(helper), "preflight"], env=force_helper_env(config), capture_output=True,
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
    helper = force_helper_checked(directory, config)
    prepared = json.loads((directory / "force-preflight.json").read_text())
    marker = force_marker(ctx, config["nonce"])
    if (config["context"] != ctx or prepared.get("trigger") != "panic-force-reset" or
            prepared.get("boot_uuid") != config["baseline"] or prepared.get("helper_sha256") != config["helper_sha256"] or
            prepared.get("marker_sha256") != hashlib.sha256(marker.encode()).hexdigest()):
        raise ValueError("force preflight changed")
    private_write(directory / "trigger.json", json.dumps(prepared).encode())
    sync_directory(directory)
    os.sync()
    result = subprocess.run([str(helper), "execute"], env=force_helper_env(config), capture_output=True,
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
                          "debug_boot": True, "debug_boot_facts": facts})
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


def collect(directory):
    config = load_config(directory)
    if (directory / "completed.json").exists():
        return
    current = boot_uuid()
    debug_facts = {}
    if reboot_observed(config["baseline"], current) and config.get("debug_boot", False):
        try:
            debug_facts = recovery_bootargs.finish(directory, debug_boot_marker(config), recovery_bootargs.MacPlatform(), private_write, sync_directory,
                                                   current_boot_uuid=current, inventory=False)
        except (OSError, ValueError, subprocess.SubprocessError):
            debug_facts = {"active_debug_mask": None, "active_bootargs_status": "unavailable", "nvram_restored": False, "current_boot_uuid": current,
                           "debugger_count": None, "debugger_inventory_status": "unavailable",
                           "network_inventory_status": "unavailable", "virtio_network_classes": [],
                           "nic_inventory_status": "unsupported", "kernel_debug_state": {}}
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
                                  "debug_boot": config.get("debug_boot", False),
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
        if debug_facts.get("nvram_restored") is True:
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
                          "debug_boot": config.get("debug_boot", False), "debug_boot_facts": debug_facts,
                          "capture_state": capture_state,
                          "cipher_sha256": envelope["cipher_sha256"] if envelope else "",
                          "note": "Boot UUID changed; no stopped-CPU GPR proof."})
    successful = config["context"].get("trigger", "reboot") == "reboot" or capture_state == "captured"
    if config.get("debug_boot", False):
        successful = successful and debug_boot_proven(debug_facts)
    output = {"title": "Recovery observed" if successful else "Panic report unavailable", "summary": summary}
    if envelope:
        output["text"] = envelope["ciphertext"]
    if len(json.dumps(output).encode()) > 58000:
        successful = False
        output = {"title": "Panic report unavailable", "summary": json.dumps({"protocol": "vz-recovery-v1",
                  "phase": "boot_observed", "binding": binding(config["context"]), "nonce": config["nonce"],
                  "baseline_boot_uuid": config["baseline"], "current_boot_uuid": current,
                  "trigger": config["context"].get("trigger", "reboot"), "cert_fingerprint": config.get("cert_fingerprint", ""),
                  "capture_state": "oversized"})}
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
        print(json.dumps({"event": "root_operation_failed", "operation": operation,
                          "returncode": proc.returncode, "root_error_kind": root_error_kind(proc.stderr)}), flush=True)
        raise RuntimeError("root operation failed")
    return proc.stdout


def controller(ctx, token):
    deadline = time.monotonic() + 600
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
                        if matches and panic_mode(ctx):
                            matches = panic_envelope_matches(data, check.get("output", {}).get("text", ""), pending, ctx)
                        if matches and check.get("conclusion") == "success":
                            print(json.dumps({"event": "controller_boot_proof", "check_id": check_id}), flush=True)
                            proof = True
                            return
                        raise ValueError("check completed without boot proof")
                    if data.get("phase") == "public_key" and data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and data.get("trigger", "reboot") == ctx.get("trigger", "reboot") and type(data.get("debug_boot", False)) is bool and data.get("debug_boot", False) == ctx.get("debug_boot", False):
                        nonce, baseline, public = data.get("nonce", ""), data.get("baseline_boot_uuid", ""), data.get("public_key", "")
                        if not re.fullmatch(r"[0-9a-f]{64}", nonce) or not re.fullmatch(r"[0-9A-Fa-f-]{36}", baseline):
                            raise ValueError("nonce or baseline invalid")
                        fingerprint = data.get("cert_fingerprint", "")
                        if panic_mode(ctx) and not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                            raise ValueError("certificate fingerprint invalid")
                        if ctx.get("trigger", "reboot") == "reboot" and fingerprint:
                            raise ValueError("unexpected certificate fingerprint")
                        if pending is None:
                            ciphertext = encrypt_token(public.encode(), token)
                            pending = {"nonce": nonce, "baseline_boot_uuid": baseline, "public_key": public,
                                       "ciphertext": base64.b64encode(ciphertext).decode(), "cert_fingerprint": fingerprint}
                        if (nonce, baseline, public, fingerprint) != (pending["nonce"], pending["baseline_boot_uuid"], pending["public_key"], pending["cert_fingerprint"]):
                            raise ValueError("public key metadata changed")
                        sealed_summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "sealed_token", "binding": binding(ctx),
                                                     "nonce": nonce, "baseline_boot_uuid": baseline, "ciphertext": pending["ciphertext"],
                                                     "trigger": ctx.get("trigger", "reboot"), "debug_boot": ctx.get("debug_boot", False),
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
                        if not ctx.get("debug_boot", False):
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
                            "force_helper": os.environ.pop("RECOVERY_FORCE_HELPER", "")}, timeout=120), end="", flush=True)
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
    elif op in ("prepare-root", "arm-root", "verify-root", "panic-preflight-root", "panic-execute-root", "force-preflight-root", "force-execute-root", "debug-request-root") and len(sys.argv) == 2:
        {"prepare-root": prepare_root, "arm-root": arm_root, "verify-root": verify_root, "panic-preflight-root": panic_preflight_root, "panic-execute-root": panic_execute_root,
         "force-preflight-root": force_preflight_root, "force-execute-root": force_execute_root,
         "debug-request-root": debug_request_root}[op](json.load(sys.stdin))
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
