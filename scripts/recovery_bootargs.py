"""A reversible, normal-reboot-only debug boot-argument transaction."""
import ctypes
import json
import os
import plistlib
import re
import selectors
import subprocess
import time


def requested(value, trigger):
    if value not in ("", "0", "1") or (value == "1" and trigger != "reboot"):
        raise ValueError("invalid debug boot request")
    return value == "1"


def text(value):
    if not isinstance(value, (str, bytes)):
        raise ValueError("boot argument type invalid")
    raw = value.encode("ascii") if isinstance(value, str) else value
    if len(raw) > 1023 or any(byte not in range(32, 127) and byte != 9 for byte in raw):
        raise ValueError("boot arguments invalid")
    return raw.decode("ascii")


def parse_nvram(raw):
    if not raw or len(raw) > 4_000_000:
        raise ValueError("NVRAM plist size invalid")
    try:
        values = plistlib.loads(raw)
    except Exception as error:
        raise ValueError("NVRAM plist invalid") from error
    if not isinstance(values, dict):
        raise ValueError("NVRAM plist type invalid")
    if any(key.endswith(":boot-args") for key in values):
        raise ValueError("ambiguous NVRAM boot arguments")
    if "boot-args" not in values:
        return {}
    text(values["boot-args"])
    return {"boot-args": values["boot-args"]}


def check_unconfigured(value):
    for token in text(value).split():
        key = token.partition("=")[0].lstrip("-")
        if key in ("debug", "_panicd_ip", "_router_ip", "_panicd_corename", "panicd_port"):
            raise ValueError("existing debugging configuration")


def desired(original):
    value = original.get("boot-args", b"")
    check_unconfigured(value)
    result = text(value) + (" " if text(value) else "") + "debug=0x2000"
    text(result)
    return {"boot-args": result if isinstance(value, str) else result.encode("ascii")}


def debug_mask(value):
    masks = []
    for token in text(value).split():
        key, sep, number = token.partition("=")
        key = key.lstrip("-")
        if key in ("_panicd_ip", "_router_ip", "_panicd_corename", "panicd_port"):
            raise ValueError("unexpected dump configuration")
        if key == "debug":
            if not sep or not re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", number):
                raise ValueError("debug mask invalid")
            masks.append(int(number, 16 if number.lower().startswith("0x") else 10))
    return masks[0] if len(masks) == 1 else None


def capture(argv, limit=4_000_000):
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    selector = selectors.DefaultSelector()
    try:
        selector.register(child.stdout, selectors.EVENT_READ)
        deadline, data = time.monotonic() + 8, bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise subprocess.TimeoutExpired(argv, 8)
            chunk = os.read(child.stdout.fileno(), min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError("platform response oversized")
        code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code:
            raise subprocess.CalledProcessError(code, argv)
        return bytes(data)
    finally:
        selector.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        child.stdout.close()


def csr_allowed():
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    library.csr_check.argtypes = [ctypes.c_uint32]
    library.csr_check.restype = ctypes.c_int
    return library.csr_check(8) == 0


class MacPlatform:
    def read(self):
        return parse_nvram(capture(["/usr/sbin/nvram", "-x", "-p"]))

    def write(self, path):
        value = parse_nvram(path.read_bytes())
        command = ["/usr/sbin/nvram", "-x", "-f", str(path)] if value else ["/usr/sbin/nvram", "-d", "boot-args"]
        capture(command)

    def active(self):
        return capture(["/usr/sbin/sysctl", "-n", "kern.bootargs"], 65536).rstrip(b"\n")

    def inventory(self):
        result = {"debugger_count": None, "virtio_network_classes": [], "nic_inventory_status": "unsupported"}
        try:
            debuggers = plistlib.loads(capture(["/usr/sbin/ioreg", "-a", "-r", "-c", "IOKernelDebugger"]))
            if isinstance(debuggers, list) and len(debuggers) <= 4096:
                result["debugger_count"] = len(debuggers)
            nodes = plistlib.loads(capture(["/usr/sbin/ioreg", "-a", "-r", "-c", "IONetworkController"]))
            stack, names, seen = [nodes], set(), 0
            while stack and seen < 4096:
                node = stack.pop()
                seen += 1
                if isinstance(node, list):
                    stack.extend(node[:4096])
                elif isinstance(node, dict):
                    for key in ("IOClass", "IOObjectClass", "IOProviderClass"):
                        name = node.get(key)
                        if isinstance(name, str) and re.fullmatch(r"AppleVirtIO[A-Za-z0-9_.-]{1,48}", name):
                            names.add(name)
                    children = node.get("IORegistryEntryChildren")
                    if isinstance(children, list):
                        stack.append(children)
            result["virtio_network_classes"] = sorted(names)[:16]
            if result["debugger_count"] is not None:
                result["nic_inventory_status"] = "observed"
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        return result


def restore(directory, marker, platform, save, sync):
    staged = json.loads((directory / "debug-boot-stage.json").read_text())
    if staged != marker:
        raise ValueError("debug boot stage identity mismatch")
    original = parse_nvram((directory / "debug-boot-original.plist").read_bytes())
    expected = parse_nvram((directory / "debug-boot-staged.plist").read_bytes())
    if desired(original) != expected:
        raise ValueError("debug boot stage value mismatch")
    current = platform.read()
    if current != original:
        if current != expected:
            raise ValueError("NVRAM changed outside transaction")
        platform.write(directory / "debug-boot-original.plist")
    if platform.read() != original:
        raise ValueError("NVRAM restoration mismatch")
    path = directory / "debug-boot-restored.json"
    if not path.exists():
        save(path, json.dumps({"nvram_restored": True}).encode())
        sync(directory)


def stage(directory, marker, platform, save, sync):
    if (directory / "debug-boot-stage.json").exists():
        raise FileExistsError("debug boot already staged")
    original = platform.read()
    expected = desired(original)
    check_unconfigured(platform.active())
    save(directory / "debug-boot-original.plist", plistlib.dumps(original))
    save(directory / "debug-boot-staged.plist", plistlib.dumps(expected))
    save(directory / "debug-boot-stage.json", json.dumps(marker).encode())
    sync(directory)
    try:
        platform.write(directory / "debug-boot-staged.plist")
        if platform.read() != expected:
            raise ValueError("NVRAM stage readback mismatch")
    except Exception:
        restore(directory, marker, platform, save, sync)
        raise


def rollback(directory, marker, platform, save, sync):
    if (directory / "debug-boot-stage.json").exists():
        restore(directory, marker, platform, save, sync)
        return
    original = directory / "debug-boot-original.plist"
    current = platform.read()
    if original.exists():
        if current != parse_nvram(original.read_bytes()):
            raise ValueError("unstaged NVRAM differs from original")
    else:
        check_unconfigured(current.get("boot-args", b""))


def finish(directory, marker, platform, save, sync):
    mask = None
    try:
        mask = debug_mask(platform.active())
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    restore(directory, marker, platform, save, sync)
    return {"active_debug_mask": mask, "nvram_restored": True, **platform.inventory()}
