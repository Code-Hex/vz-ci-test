#!/usr/bin/env python3
"""Read a filtered kernel-debugging platform inventory on the Intel runner."""
import ctypes
import json
import os
from pathlib import Path
import plistlib
import re
import selectors
import subprocess
import sys
import time
from xml.parsers.expat import ExpatError

UUID = "87453B1D-A163-31FA-B33B-0FB4BE78E6E8"
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


def parse_bootargs(text):
    masks = []
    panicd, router = False, False
    for token in text.split()[:1024]:
        key, sep, value = token.partition("=")
        key = key.lstrip("-")
        if key == "debug" and sep and re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})", value):
            number = int(value, 16 if value.lower().startswith("0x") else 10)
            if number < 2**64 and len(masks) < 8:
                masks.append(number)
        elif key == "_panicd_ip":
            panicd = True
        elif key == "_router_ip":
            router = True
    return {"debug_masks": masks, "panicd_present": panicd, "router_present": router}


def parse_sip(text):
    sip, debugging = "unknown", "unknown"
    for line in text.splitlines()[:128]:
        line = line.strip()
        match = re.fullmatch(r"System Integrity Protection status: (enabled|disabled|custom configuration)\.", line, re.I)
        if match:
            state = match.group(1).lower()
            sip = "custom" if state == "custom configuration" else state
        match = re.fullmatch(r"Kernel Debugging: (enabled|disabled)\.?", line, re.I)
        if match:
            debugging = match.group(1).lower()
    return {"sip": sip, "kernel_debugging": debugging}


def parse_network(data):
    root = plistlib.loads(data)
    if not isinstance(root, list):
        raise ValueError("invalid_plist")
    result, visited, stack = [], 0, [(root, 0)]
    while stack and visited < 4096 and len(result) < 64:
        node, depth = stack.pop()
        visited += 1
        if depth > 16:
            continue
        if isinstance(node, list):
            stack.extend((item, depth + 1) for item in reversed(node[:4096]))
        elif isinstance(node, dict):
            item = {}
            for key in ("IOClass", "IOProviderClass", "IOInterfaceName"):
                value = node.get(key)
                if isinstance(value, str) and IDENTIFIER.fullmatch(value):
                    item[key] = value
            if item:
                result.append(item)
            children = node.get("IORegistryEntryChildren")
            if isinstance(children, list):
                stack.append((children, depth + 1))
    return result


def parse_devices(data, watchdog):
    root = plistlib.loads(data)
    if not isinstance(root, list) or len(root) > 64 or any(not isinstance(node, dict) for node in root):
        raise ValueError("invalid_plist")
    nodes = []
    for node in root:
        item = {}
        for key in ("IOClass", "IOProviderClass"):
            value = node.get(key)
            if isinstance(value, str) and IDENTIFIER.fullmatch(value):
                item[key] = value
        if watchdog and type(node.get("IOWatchDogEnabled")) is bool:
            item["IOWatchDogEnabled"] = node["IOWatchDogEnabled"]
        nodes.append(item)
    return {"count": len(root), "nodes": nodes}


def parse_panic_nvram(data):
    root = plistlib.loads(data)
    if not isinstance(root, dict) or set(root) != {"aapl,panic-info"}:
        raise ValueError("invalid_plist")
    value = root["aapl,panic-info"]
    if isinstance(value, bytes):
        return {"type": "data", "size": len(value)}
    if isinstance(value, str):
        return {"type": "string", "size": len(value.encode("utf-8"))}
    if type(value) is bool:
        return {"type": "boolean", "size": None}
    if type(value) is int:
        return {"type": "integer", "size": None}
    raise ValueError("invalid_type")


def count_debuggers(data):
    root = plistlib.loads(data)
    if not isinstance(root, list) or len(root) > 4096:
        raise ValueError("invalid_plist")
    return len(root)


def command(argv, limit):
    child = None
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        deadline, data = time.monotonic() + 8, bytearray()
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "timeout", None
                if not selector.select(remaining):
                    return "timeout", None
                chunk = os.read(child.stdout.fileno(), min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    return "too_large", None
            try:
                code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                return "timeout", None
            return ("ok", bytes(data)) if code == 0 else ("unavailable", None)
        finally:
            selector.close()
    except (OSError, subprocess.SubprocessError):
        return "unavailable", None
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            if child.stdout:
                child.stdout.close()


def main():
    if (len(sys.argv) != 1 or not os.environ.get("RUNNER_TEMP")
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "Code-Hex/vz-ci-test"
            or os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ATTEMPT", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", ""))
            or sys.platform != "darwin" or os.uname().machine != "x86_64"):
        print('{"event":"error","reason":"invalid_context"}', flush=True)
        return 2
    status, value = command(["/usr/sbin/sysctl", "-n", "kern.uuid"], 1024)
    if status != "ok" or value.decode("ascii", "replace").strip().upper() != UUID:
        print('{"event":"error","reason":"kernel_uuid_mismatch"}', flush=True)
        return 2
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        check = library.csr_check
        check.argtypes = [ctypes.c_uint32]
        check.restype = ctypes.c_int
        csr_result = int(check(1 << 3))
    except (OSError, AttributeError):
        csr_result = None
    commands = {
        "bootargs": (["/usr/sbin/sysctl", "-n", "kern.bootargs"], 65536, lambda x: parse_bootargs(x.decode("utf-8", "replace"))),
        "nvram_bootargs": (["/usr/sbin/nvram", "boot-args"], 65536, lambda x: parse_bootargs(x.decode("utf-8", "replace"))),
        "sip": (["/usr/bin/csrutil", "status"], 65536, lambda x: parse_sip(x.decode("utf-8", "replace"))),
        "network": (["/usr/sbin/ioreg", "-a", "-r", "-c", "IONetworkController"], 4_000_000, parse_network),
        "debuggers": (["/usr/sbin/ioreg", "-a", "-r", "-c", "IOKernelDebugger"], 1_000_000, count_debuggers),
        "nvram_controller": (["/usr/sbin/ioreg", "-a", "-r", "-c", "IONVRAMController"], 1_000_000, lambda x: parse_devices(x, False)),
        "watchdog": (["/usr/sbin/ioreg", "-a", "-r", "-c", "IOWatchDogTimer"], 1_000_000, lambda x: parse_devices(x, True)),
        "panic_nvram": (["/usr/sbin/nvram", "-x", "aapl,panic-info"], 1_000_000, parse_panic_nvram),
    }
    result = {"event": "kdp_platform_inventory", "kernel_uuid": UUID,
              "csr_allow_kernel_debugger_result": csr_result}
    for name, (argv, limit, parser) in commands.items():
        status, data = command(argv, limit)
        value = None
        if status == "ok":
            try:
                value = parser(data)
            except (ValueError, TypeError, plistlib.InvalidFileException, ExpatError):
                status = "invalid"
        result[name] = {"status": status, "value": value}
    directory = Path(os.environ["RUNNER_TEMP"]) / "debug"
    directory.mkdir(parents=True, exist_ok=True)
    output = json.dumps(result, separators=(",", ":"))
    (directory / "kdp-platform.json").write_text(output + "\n", encoding="utf-8")
    print(output, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
