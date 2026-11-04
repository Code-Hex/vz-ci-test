"""Generate a shell entry point that reports before the Python collector."""
import hashlib
import json
import ipaddress
import re
import shlex
import socket
from pathlib import Path

VERSION = "boot-arrival-v1"
URL = "https://api.github.com/repos/Code-Hex/vz-ci-test/check-runs"
UUID = re.compile(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\Z")


def authorization_header(token):
    if not isinstance(token, str) or not token or len(token) > 446 or any(not 33 <= ord(char) <= 126 for char in token):
        raise ValueError("arrival credential invalid")
    return ("Authorization: Bearer " + token + "\n").encode("ascii")


def resolve_api():
    try:
        return next((item[4][0] for item in socket.getaddrinfo("api.github.com", 443, socket.AF_INET, socket.SOCK_STREAM)
                     if ipaddress.IPv4Address(item[4][0]).is_global), "")
    except (OSError, ValueError):
        return ""


def render(config, directory):
    ctx = config["context"]
    if (ctx.get("repo") != "Code-Hex/vz-ci-test" or
            not re.fullmatch(r"[1-9][0-9]{0,19}", ctx.get("run_id", "")) or
            not re.fullmatch(r"[1-9][0-9]{0,4}", ctx.get("attempt", "")) or
            not re.fullmatch(r"[0-9a-f]{40}", ctx.get("sha", "")) or
            not UUID.fullmatch(config.get("baseline", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", config.get("nonce", "")) or
            not Path(config["python"]).is_absolute() or not Path(directory).is_absolute()):
        raise ValueError("arrival identity invalid")
    binding = "/".join((ctx["run_id"], ctx["attempt"], ctx["sha"], config["nonce"]))
    api_ip = config.get("arrival_api_ipv4", "")
    if not isinstance(api_ip, str) or api_ip and not ipaddress.IPv4Address(api_ip).is_global:
        raise ValueError("arrival API address invalid")
    summary = json.dumps({"protocol": VERSION, "binding": binding, "baseline_boot_uuid": config["baseline"],
                          "actual_boot_uuid": "BOOT_VALUE", "kernel_uuid": "KERNEL_VALUE", "system": "SYSTEM_VALUE",
                          "machine": "MACHINE_VALUE", "vmm": "VMM_VALUE", "kernel_status": "KERNEL_STATUS", "vmm_status": "VMM_STATUS",
                          "python_path_status": "PYTHON_PATH_STATUS",
                          "source_generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    payload = {"name": "Boot arrival " + ctx["run_id"], "head_sha": ctx["sha"], "external_id": binding + "/BOOT_EXTERNAL",
               "status": "completed", "conclusion": "neutral",
               "output": {"title": "LaunchDaemon reached before Python", "summary": summary}}
    body = json.dumps(payload, separators=(",", ":")).replace("\\", "\\\\").replace("%", "%%")
    names = {"BOOT_EXTERNAL": "$boot", "BOOT_VALUE": "$boot", "KERNEL_VALUE": "$kernel", "SYSTEM_VALUE": "$system",
             "MACHINE_VALUE": "$machine", "VMM_VALUE": "$vmm", "KERNEL_STATUS": "$kernel_status", "VMM_STATUS": "$vmm_status",
             "PYTHON_PATH_STATUS": "$python_path_status"}
    ordered = sorted(names, key=body.index)
    for name in ordered:
        body = body.replace(name, "%s")
    arguments = " ".join('"' + names[name] + '"' for name in ordered)
    script = '''#!/bin/sh
umask 077
directory=DIRECTORY
python=PYTHON
baseline=BASELINE
hex='[0123456789abcdefABCDEF]'
h4=$hex$hex$hex$hex
uuid() { case "$1" in $h4$h4-$h4-$h4-$h4-$h4$h4$h4) return 0;; *) return 1;; esac; }
boot=$(/usr/sbin/sysctl -n kern.bootsessionuuid 2>/dev/null | /usr/bin/tr 'a-f' 'A-F') || boot=
if uuid "$boot" && [ "$boot" != "$baseline" ] && [ ! -f "$directory/arrival-$boot.posted" ]; then
    kernel=$(/usr/sbin/sysctl -n kern.uuid 2>/dev/null) || kernel=
    if uuid "$kernel"; then kernel_status=observed; else kernel=unknown; kernel_status=unavailable; fi
    system=$(/usr/bin/uname -s 2>/dev/null) || system=unknown
    case "$system" in Darwin|Linux) ;; *) system=unknown;; esac
    machine=$(/usr/bin/uname -m 2>/dev/null) || machine=unknown
    case "$machine" in x86_64|arm64) ;; *) machine=unknown;; esac
    vmm=$(/usr/sbin/sysctl -n kern.hv_vmm_present 2>/dev/null) || vmm=unknown
    case "$vmm" in 0|1) vmm_status=observed;; *) vmm=unknown; vmm_status=unavailable;; esac
    if [ -f "$python" ] && [ -x "$python" ]; then python_path_status=file_executable; else python_path_status=unavailable; fi
    body="$directory/arrival-$boot.request.json"
    if [ ! -e "$body" ]; then
        (set -C; printf BODY_FORMAT BODY_ARGUMENTS > "$body") 2>/dev/null
    fi
    if [ -f "$body" ] && [ ! -L "$body" ]; then
        code=$(/usr/bin/curl --disable --silent --proto '=https' --connect-timeout 3 --max-time 8 --request POST RESOLVE_OPTION \\
            --header "@$directory/arrival.headers" --header 'Content-Type: application/json' \\
            --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \\
            --data-binary "@$body" --output /dev/null --write-out '%{http_code}' FIXED_URL 2>/dev/null) || code=000
        if [ "$code" = 201 ]; then
            (set -C; printf 'posted\\n' > "$directory/arrival-$boot.posted") 2>/dev/null
        fi
    fi
fi
exec "$python" "$directory/recovery.py" collect "$directory"
'''
    for name, value in {"DIRECTORY": shlex.quote(str(directory)), "PYTHON": shlex.quote(config["python"]),
                        "BASELINE": shlex.quote(config["baseline"].upper()), "BODY_FORMAT": shlex.quote(body),
                        "BODY_ARGUMENTS": arguments, "FIXED_URL": shlex.quote(URL),
                        "RESOLVE_OPTION": "--resolve " + shlex.quote("api.github.com:443:" + api_ip) if api_ip else ""}.items():
        script = script.replace(name, value)
    return script.encode("utf-8")
