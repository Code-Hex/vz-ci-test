#!/usr/bin/env python3
"""Normal-reboot proof through a second job's sealed check-run credential."""
import base64
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
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
              ctx.get("runner_environment") == "github-hosted" and
              bool(re.fullmatch(r"[1-9][0-9]{0,19}", str(ctx.get("run_id", "")))) and
              bool(re.fullmatch(r"[1-9][0-9]{0,4}", str(ctx.get("attempt", "")))) and
              bool(re.fullmatch(r"[0-9a-f]{40}", str(ctx.get("sha", "")))))
    return bool(common and machine == "x86_64" and
                ((system == "Darwin" and str(kernel_uuid).upper() == KERNEL_UUID) or system == "Linux"))


def binding(ctx):
    return ctx["run_id"] + "/" + ctx["attempt"] + "/" + ctx["sha"]


def details_url(ctx):
    return "https://github.com/Code-Hex/vz-ci-test/actions/runs/" + ctx["run_id"] + "/attempts/" + ctx["attempt"]


def select_check(checks, ctx):
    matches = [c for c in checks if c.get("name") == "Runner recovery " + ctx["run_id"] and
               c.get("external_id") == binding(ctx) and c.get("head_sha") == ctx["sha"] and
               c.get("app", {}).get("slug") == "github-actions" and c.get("app", {}).get("id") == 15368 and
               c.get("details_url") == details_url(ctx)]
    if len(matches) > 1:
        raise ValueError("duplicate matching check")
    return matches[0] if matches else None


def reboot_observed(before, after):
    return bool(before and after and before != after)


def armed_matches(data, pending, ctx):
    return (data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and
            data.get("phase") == "armed" and data.get("nonce") == pending["nonce"] and
            data.get("baseline_boot_uuid") == pending["baseline_boot_uuid"])


def sealed_matches(data, pending, ctx):
    return (data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and
            data.get("phase") == "sealed_token" and data.get("nonce") == pending["nonce"] and
            data.get("baseline_boot_uuid") == pending["baseline_boot_uuid"] and
            data.get("ciphertext") == pending["ciphertext"])


def boot_proof_matches(data, pending, ctx):
    return (data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx) and
            data.get("phase") == "boot_observed" and data.get("nonce") == pending["nonce"] and
            data.get("baseline_boot_uuid") == pending["baseline_boot_uuid"] and
            reboot_observed(pending["baseline_boot_uuid"], data.get("current_boot_uuid")))


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
    return {"actions": os.getenv("GITHUB_ACTIONS", ""), "repo": os.getenv("GITHUB_REPOSITORY", ""),
            "ref": os.getenv("GITHUB_REF", ""), "event": os.getenv("GITHUB_EVENT_NAME", ""),
            "runner_environment": os.getenv("RUNNER_ENVIRONMENT", ""), "run_id": os.getenv("GITHUB_RUN_ID", ""),
            "attempt": os.getenv("GITHUB_RUN_ATTEMPT", ""), "sha": os.getenv("GITHUB_SHA", "")}


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
    directory = root_dir(ctx)
    directory.mkdir(mode=0o700)
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
                          "nonce": nonce, "baseline_boot_uuid": baseline, "public_key": public})
    check = api("POST", CHECKS, token, {"name": "Runner recovery " + ctx["run_id"], "head_sha": ctx["sha"],
                "external_id": binding(ctx), "details_url": details_url(ctx), "status": "in_progress",
                "output": {"title": "Awaiting controller", "summary": summary}})
    if not isinstance(check.get("id"), int) or check["id"] <= 0:
        raise ValueError("invalid check identifier")
    config = {"context": ctx, "baseline": baseline, "check_id": check["id"], "nonce": nonce, "python": python}
    private_write(directory / "config.json", json.dumps(config).encode())
    private_write(directory / "recovery.py", Path(__file__).read_bytes())
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
    if data.get("protocol") != "vz-recovery-v1" or data.get("binding") != binding(ctx) or data.get("nonce") != config["nonce"] or data.get("baseline_boot_uuid") != config["baseline"]:
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
    private_write(directory / "token", token.encode())
    label = "com.vz.ci.recovery." + ctx["run_id"] + "." + ctx["attempt"]
    plist = Path("/Library/LaunchDaemons") / (label + ".plist")
    python = config["python"]
    if not Path(python).is_file() or not os.access(python, os.X_OK) or str(Path(python).resolve()) != python:
        raise ValueError("daemon Python executable changed")
    data = plistlib.dumps({"Label": label, "ProgramArguments": [python, str(directory / "recovery.py"), "collect", str(directory)],
                           "RunAtLoad": True, "StandardOutPath": str(directory / "launchd.log"),
                           "StandardErrorPath": str(directory / "launchd.log")})
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


def collect(directory):
    config = load_config(directory)
    if (directory / "completed.json").exists():
        return
    current = boot_uuid()
    token = (directory / "token").read_text()
    if not reboot_observed(config["baseline"], current):
        if not (directory / "ready.json").exists():
            summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "armed", "binding": binding(config["context"]),
                                  "nonce": config["nonce"], "baseline_boot_uuid": config["baseline"]})
            api("PATCH", CHECKS + "/" + str(config["check_id"]), token,
                {"output": {"title": "Recovery daemon ready", "summary": summary}})
            private_write(directory / "ready.json", json.dumps({"baseline": config["baseline"], "nonce": config["nonce"],
                                                                 "preboot_patch": True, "ready": True}).encode())
            sync_directory(directory)
        return
    ready = json.loads((directory / "ready.json").read_text())
    if ready.get("preboot_patch") is not True or ready.get("baseline") != config["baseline"] or ready.get("nonce") != config["nonce"]:
        raise ValueError("preboot confirmation missing")
    summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": binding(config["context"]),
                          "nonce": config["nonce"], "baseline_boot_uuid": config["baseline"], "current_boot_uuid": current,
                          "note": "Normal reboot boot UUID changed; no stopped-CPU GPR proof."})
    payload = {"status": "completed", "conclusion": "success",
               "output": {"title": "Normal reboot observed", "summary": summary}}
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            api("PATCH", CHECKS + "/" + str(config["check_id"]), token, payload,
                timeout=min(10, max(0.1, deadline - time.monotonic())))
            private_write(directory / "completed.json", json.dumps({"boot_uuid": current}).encode())
            (directory / "token").unlink()
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


def sudo_call(operation, payload, timeout=40):
    proc = subprocess.run(["/usr/bin/sudo", "-n", sys.executable, str(Path(__file__).resolve()), operation],
                          input=json.dumps(payload), text=True, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        print(json.dumps({"event": "root_operation_failed", "operation": operation,
                          "returncode": proc.returncode, "root_error_kind": root_error_kind(proc.stderr)}), flush=True)
        raise RuntimeError("root operation failed")
    return proc.stdout


def controller(ctx, token):
    deadline = time.monotonic() + 600
    check_id = None
    pending = None
    sealed = False
    while time.monotonic() < deadline:
        try:
            check = list_check(ctx, token)
            if check:
                if check_id is not None and check_id != check["id"]:
                    raise ValueError("check identity changed")
                check_id = check["id"]
                data = json.loads(check.get("output", {}).get("summary", "{}"))
                if check.get("status") == "completed":
                    if (pending is not None and check.get("conclusion") == "success" and
                            boot_proof_matches(data, pending, ctx)):
                        print(json.dumps({"event": "controller_boot_proof", "check_id": check_id}), flush=True)
                        return
                    raise ValueError("check completed without boot proof")
                if data.get("phase") == "public_key" and data.get("protocol") == "vz-recovery-v1" and data.get("binding") == binding(ctx):
                    nonce, baseline, public = data.get("nonce", ""), data.get("baseline_boot_uuid", ""), data.get("public_key", "")
                    if not re.fullmatch(r"[0-9a-f]{64}", nonce) or not re.fullmatch(r"[0-9A-Fa-f-]{36}", baseline):
                        raise ValueError("nonce or baseline invalid")
                    if pending is None:
                        ciphertext = encrypt_token(public.encode(), token)
                        pending = {"nonce": nonce, "baseline_boot_uuid": baseline, "public_key": public,
                                   "ciphertext": base64.b64encode(ciphertext).decode()}
                    if (nonce, baseline, public) != (pending["nonce"], pending["baseline_boot_uuid"], pending["public_key"]):
                        raise ValueError("public key metadata changed")
                    sealed_summary = json.dumps({"protocol": "vz-recovery-v1", "phase": "sealed_token", "binding": binding(ctx),
                                                 "nonce": nonce, "baseline_boot_uuid": baseline, "ciphertext": pending["ciphertext"]})
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
    if check_id is not None:
        try:
            current = api("GET", CHECKS + "/" + str(check_id), token, timeout=5)
            if select_check([current], ctx) is not None and current.get("status") != "completed":
                api("PATCH", CHECKS + "/" + str(check_id), token,
                    {"status": "completed", "conclusion": "failure", "output": {"title": "Recovery not observed",
                     "summary": "Controller timed out; this does not prove a reboot or kernel failure."}}, timeout=5)
        except (OSError, urllib.error.URLError, ValueError):
            pass
    raise RuntimeError("controller timed out")


def main():
    if len(sys.argv) < 2:
        raise ValueError("usage: reboot-recovery.py prepare|arm|reboot|controller")
    op = sys.argv[1]
    if op in ("prepare", "arm", "reboot", "controller") and len(sys.argv) == 2:
        ctx = context_from_env()
        require_context(ctx, "Linux" if op == "controller" else "Darwin")
        token = os.environ.pop("GITHUB_TOKEN", "") if op != "reboot" else ""
        if op != "reboot" and not token:
            raise ValueError("GITHUB_TOKEN missing")
        if op == "controller":
            controller(ctx, token)
        elif op == "prepare":
            print(sudo_call("prepare-root", {"context": ctx, "token": token}, timeout=120), end="", flush=True)
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
        else:
            print(sudo_call("verify-root", {"context": ctx}), end="", flush=True)
            os.sync()
            subprocess.run(["/usr/bin/sudo", "-n", "/sbin/reboot"], check=True, timeout=15)
    elif op in ("prepare-root", "arm-root", "verify-root") and len(sys.argv) == 2:
        {"prepare-root": prepare_root, "arm-root": arm_root, "verify-root": verify_root}[op](json.load(sys.stdin))
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
