"""A reversible debug boot-argument transaction for normal and quick reboot."""
import ctypes
import json
import os
import plistlib
import re
import selectors
import subprocess
import time

CANARY_KEY = "vz-ci-persistence-probe"
OWNED_KEYS = ("boot-args", CANARY_KEY)


class ForeignNVRAM(ValueError):
    pass


def requested(value, trigger):
    if value not in ("", "0", "1") or (value == "1" and trigger not in ("reboot", "reboot-quick")):
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
    if any(isinstance(key, str) and any(key.endswith(":" + owned) for owned in OWNED_KEYS) for key in values):
        raise ValueError("ambiguous NVRAM boot arguments")
    if "boot-args" in values:
        text(values["boot-args"])
    return {key: values[key] for key in OWNED_KEYS if key in values}


def check_unconfigured(value):
    for token in text(value).split():
        key = token.partition("=")[0].lstrip("-")
        if key in ("debug", "_panicd_ip", "_router_ip", "_panicd_corename", "panicd_port"):
            raise ValueError("existing debugging configuration")


def canary_value(marker):
    binding, nonce = marker.get("binding", ""), marker.get("nonce", "")
    if (not isinstance(binding, str) or not re.fullmatch(r"[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}", binding) or
            not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce)):
        raise ValueError("canary scope invalid")
    run, attempt, _sha = binding.split("/")
    return ("v1:" + run + ":" + attempt + ":" + nonce).encode("ascii")


def desired(original, marker):
    if CANARY_KEY in original:
        raise ValueError("existing persistence canary")
    value = original.get("boot-args", b"")
    check_unconfigured(value)
    result = text(value) + (" " if text(value) else "") + "debug=0x2000"
    text(result)
    return {"boot-args": result if isinstance(value, str) else result.encode("ascii"), CANARY_KEY: canary_value(marker)}


def key_states(original, staged, current):
    def same(left, right, key):
        return (key in left) == (key in right) and (key not in left or
                type(left[key]) is type(right[key]) and left[key] == right[key])
    states = {name: "original" if same(current, original, key) else "staged" if same(current, staged, key) else "other"
              for name, key in (("boot_args", "boot-args"), ("canary", CANARY_KEY))}
    return whole_state(states), states


def whole_state(states):
    return "other" if "other" in states.values() else \
           "original" if all(value == "original" for value in states.values()) else \
           "staged" if all(value == "staged" for value in states.values()) else "partial"


def valid_key_states(states, allow_other=False):
    return (isinstance(states, dict) and set(states) == {"boot_args", "canary"} and
            all(value in (("original", "staged", "other") if allow_other else ("original", "staged")) for value in states.values()))


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
    if len(masks) > 1 or (masks and masks[0] > 0xffffffff):
        raise ValueError("ambiguous debug mask")
    return masks[0] if masks else None


def capture(argv, limit=4_000_000, timeout=8):
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    selector = selectors.DefaultSelector()
    try:
        selector.register(child.stdout, selectors.EVENT_READ)
        deadline, data = time.monotonic() + timeout, bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise subprocess.TimeoutExpired(argv, timeout)
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


def ioreg_nodes(raw):
    try:
        value = plistlib.loads(raw)
    except Exception as error:
        raise ValueError("IORegistry plist invalid") from error
    if not isinstance(value, list) or len(value) > 4096:
        raise ValueError("IORegistry plist type invalid")
    return value


KERNEL_FIELDS = {
    "debug_boot_arg": ("(uint32_t)`debug_boot_arg", 0xffffffff),
    "kdp_flag": ("(uint32_t)`kdp_flag", 0xffffffff),
    "send_registered": ("`kdp_en_send_pkt != 0", 1),
    "receive_registered": ("`kdp_en_recv_pkt != 0", 1),
}


def kernel_debug_state():
    result = {}
    for name, (expression, maximum) in KERNEL_FIELDS.items():
        source = 'dtrace:::BEGIN { printf("%llu\\n", (uint64_t)(' + expression + ')); exit(0); }'
        try:
            raw = capture(["/usr/sbin/dtrace", "-q", "-n", source], 4096, timeout=5)
            if not re.fullmatch(rb"[0-9]{1,10}\n?", raw) or int(raw) > maximum:
                raise ValueError("kernel debug value invalid")
            value = bool(int(raw)) if maximum == 1 else int(raw)
            result[name] = {"status": "observed", "value": value}
        except (OSError, subprocess.SubprocessError):
            result[name] = {"status": "unavailable"}
        except ValueError:
            result[name] = {"status": "invalid"}
    return result


class MacPlatform:
    def read(self):
        return parse_nvram(capture(["/usr/sbin/nvram", "-x", "-p"]))

    def write(self, path, owned_canary, expected_previous):
        value = parse_nvram(path.read_bytes())
        current = self.read()
        if key_states(expected_previous, expected_previous, current)[0] != "original":
            raise ForeignNVRAM("NVRAM changed before write")
        for record in (current, value):
            if CANARY_KEY in record and (type(record[CANARY_KEY]) is not bytes or record[CANARY_KEY] != owned_canary):
                raise ForeignNVRAM("foreign persistence canary")
        if value:
            capture(["/usr/sbin/nvram", "-x", "-f", str(path)])
        for key in OWNED_KEYS:
            if key in current and key not in value:
                capture(["/usr/sbin/nvram", "-d", key])
        capture(["/usr/sbin/nvram", "-s"])

    def active(self):
        raw = capture(["/usr/sbin/sysctl", "-n", "kern.bootargs"], 65536)
        if not raw:
            raise ValueError("boot argument response empty")
        return raw.rstrip(b"\n")

    def inventory(self):
        result = {"debugger_count": None, "virtio_network_classes": [], "nic_inventory_status": "unsupported",
                  "debugger_inventory_status": "unavailable", "network_inventory_status": "unavailable"}
        try:
            debuggers = ioreg_nodes(capture(["/usr/sbin/ioreg", "-a", "-r", "-c", "IOKernelDebugger"]))
            result["debugger_count"] = len(debuggers)
            result["debugger_inventory_status"] = "observed"
        except (OSError, subprocess.SubprocessError):
            pass
        except ValueError:
            result["debugger_inventory_status"] = "invalid"
        try:
            nodes = ioreg_nodes(capture(["/usr/sbin/ioreg", "-a", "-r", "-c", "IONetworkController"]))
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
            result["network_inventory_status"] = "observed"
        except (OSError, subprocess.SubprocessError):
            pass
        except ValueError:
            result["network_inventory_status"] = "invalid"
        if result["debugger_inventory_status"] == result["network_inventory_status"] == "observed":
            result["nic_inventory_status"] = "observed"
        result["kernel_debug_state"] = kernel_debug_state()
        return result


def restore(directory, marker, platform, save, sync, before_restore=None, *, cause="unspecified", current_boot_uuid=None):
    staged = json.loads((directory / "debug-boot-stage.json").read_text())
    if staged != marker:
        raise ValueError("debug boot stage identity mismatch")
    original = parse_nvram((directory / "debug-boot-original.plist").read_bytes())
    expected = parse_nvram((directory / "debug-boot-staged.plist").read_bytes())
    if desired(original, marker) != expected:
        raise ValueError("debug boot stage value mismatch")
    current = platform.read()
    state, states = key_states(original, expected, current)
    if not valid_key_states(states):
        if before_restore is not None:
            before_restore(state, states)
        raise ForeignNVRAM("NVRAM changed outside transaction")
    try:
        if before_restore is not None:
            before_restore(state, states)
    finally:
        platform.write(directory / "debug-boot-original.plist", canary_value(marker), current)
        if platform.read() != original:
            raise ValueError("NVRAM restoration mismatch")
        path = directory / "debug-boot-restored.json"
        if not path.exists():
            save(path, json.dumps({"nvram_restored": True, "marker": marker, "cause": cause,
                                   "actual_boot_uuid": current_boot_uuid or marker.get("baseline"),
                                   "nvram_before_restore": state, "nvram_key_states": states}).encode())
            sync(directory)
    return state


def stage(directory, marker, platform, save, sync):
    if (directory / "debug-boot-stage.json").exists():
        raise FileExistsError("debug boot already staged")
    original = platform.read()
    expected = desired(original, marker)
    check_unconfigured(platform.active())
    save(directory / "debug-boot-original.plist", plistlib.dumps(original))
    save(directory / "debug-boot-staged.plist", plistlib.dumps(expected))
    save(directory / "debug-boot-stage.json", json.dumps(marker).encode())
    sync(directory)
    try:
        platform.write(directory / "debug-boot-staged.plist", canary_value(marker), original)
        if platform.read() != expected:
            raise ValueError("NVRAM stage readback mismatch")
    except Exception:
        restore(directory, marker, platform, save, sync, cause="stage_failure")
        raise


def rollback(directory, marker, platform, save, sync):
    if (directory / "debug-boot-stage.json").exists():
        return restore(directory, marker, platform, save, sync, cause="preintent_abort")
    original = directory / "debug-boot-original.plist"
    current = platform.read()
    if original.exists():
        if current != parse_nvram(original.read_bytes()):
            raise ValueError("unstaged NVRAM differs from original")
    else:
        check_unconfigured(current.get("boot-args", b""))
        if CANARY_KEY in current:
            raise ValueError("unstaged persistence canary")
    return "unstaged"


def receipt_summary(data):
    if not isinstance(data, dict) or data.get("status") not in ("absent", "invalid", "observed"):
        return {"status": "invalid"}
    if data["status"] != "observed":
        return {"status": data["status"]}
    if (data.get("cause") not in ("stage_failure", "preintent_abort", "postboot") or
            not isinstance(data.get("actual_boot_uuid"), str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", data["actual_boot_uuid"]) or
            not valid_key_states(data.get("nvram_key_states")) or data.get("nvram_before_restore") != whole_state(data["nvram_key_states"])):
        return {"status": "invalid"}
    return {key: data[key] for key in ("status", "cause", "actual_boot_uuid", "nvram_before_restore", "nvram_key_states")}


def finish(directory, marker, platform, save, sync, *, current_boot_uuid, inventory=True):
    if not isinstance(current_boot_uuid, str) or not current_boot_uuid:
        raise ValueError("observation boot identity absent")
    facts = {"active_debug_mask": None, "active_bootargs_status": "unavailable", "current_boot_uuid": current_boot_uuid,
             "restored_marker_preexisting": (directory / "debug-boot-restored.json").exists()}
    receipt = directory / "debug-boot-restored.json"
    facts["restore_receipt"] = {"status": "absent"}
    if receipt.exists():
        facts["restore_receipt"] = {"status": "invalid"}
        try:
            data = json.loads(receipt.read_text())
            if isinstance(data, dict) and data.get("marker") == marker and data.get("nvram_restored") is True:
                facts["restore_receipt"] = receipt_summary({"status": "observed", **data})
        except (OSError, ValueError):
            pass
    try:
        facts["active_debug_mask"] = debug_mask(platform.active())
        facts["active_bootargs_status"] = "observed_no_debug" if facts["active_debug_mask"] is None else "observed_debug"
    except (OSError, subprocess.SubprocessError):
        pass
    except ValueError:
        facts["active_bootargs_status"] = "invalid"

    def record(state, states):
        path = directory / "debug-boot-observed.json"
        if path.exists():
            previous = json.loads(path.read_text())
            if (not isinstance(previous, dict) or previous.get("marker") != marker or
                    previous.get("current_boot_uuid") != current_boot_uuid or previous.get("active_bootargs_status") not in
                    ("observed_no_debug", "observed_debug", "unavailable", "invalid") or
                    not valid_key_states(previous.get("nvram_key_states"), allow_other=True) or
                    previous.get("nvram_before_restore") != whole_state(previous["nvram_key_states"]) or
                    not (previous.get("active_debug_mask") is None or
                         type(previous["active_debug_mask"]) is int and 0 <= previous["active_debug_mask"] <= 0xffffffff)):
                raise ValueError("debug observation invalid")
            if (previous["active_bootargs_status"] == "observed_debug") != (type(previous["active_debug_mask"]) is int):
                raise ValueError("debug observation inconsistent")
            if type(previous.get("restored_marker_preexisting")) is not bool:
                raise ValueError("restoration observation invalid")
            facts.update({key: previous[key] for key in ("active_bootargs_status", "active_debug_mask", "nvram_before_restore", "nvram_key_states", "restored_marker_preexisting")})
            facts["restore_receipt"] = receipt_summary(previous.get("restore_receipt"))
        else:
            facts["nvram_before_restore"] = state
            facts["nvram_key_states"] = states
            save(path, json.dumps({"marker": marker, **facts}).encode())
            sync(directory)

    try:
        restore(directory, marker, platform, save, sync, before_restore=record, cause="postboot", current_boot_uuid=current_boot_uuid)
    except ForeignNVRAM:
        return {**facts, "nvram_restored": False}
    return {**facts, "nvram_restored": True, **(platform.inventory() if inventory else {})}


def optional_summary(data):
    result = {}
    if not isinstance(data, dict):
        return result
    count = data.get("debugger_count")
    if count is None or type(count) is int and 0 <= count <= 4096:
        result["debugger_count"] = count
    names = data.get("virtio_network_classes")
    if isinstance(names, list):
        result["virtio_network_classes"] = [name for name in names[:16] if isinstance(name, str) and re.fullmatch(r"AppleVirtIO[A-Za-z0-9_.-]{1,48}", name)]
    for key in ("nic_inventory_status", "debugger_inventory_status", "network_inventory_status"):
        if data.get(key) in ("observed", "unsupported", "unavailable", "invalid"):
            result[key] = data[key]
    states = data.get("kernel_debug_state")
    if isinstance(states, dict):
        result["kernel_debug_state"] = {}
        for name, (_expr, maximum) in KERNEL_FIELDS.items():
            value = states.get(name)
            if not isinstance(value, dict) or value.get("status") not in ("observed", "unavailable", "invalid"):
                continue
            record = {"status": value["status"]}
            number = value.get("value")
            if record["status"] == "observed":
                if maximum == 1 and type(number) is bool or maximum != 1 and type(number) is int and 0 <= number <= maximum:
                    record["value"] = number
                else:
                    record["status"] = "invalid"
            result["kernel_debug_state"][name] = record
    return result


def observe_once(directory, marker, platform, save, sync, *, current_boot_uuid):
    scope = {"marker": marker, "current_boot_uuid": current_boot_uuid}
    started = directory / "debug-boot-inventory-started.json"
    result = directory / "debug-boot-inventory-result.json"
    if started.exists():
        if json.loads(started.read_text()) != scope:
            return {"optional_inventory_status": "scope_mismatch"}
        if not result.exists():
            return {"optional_inventory_status": "uncertain"}
        raw = result.read_bytes()
        if len(raw) > 16384:
            return {"optional_inventory_status": "invalid"}
        saved = json.loads(raw)
        if not isinstance(saved, dict) or saved.get("scope") != scope or not isinstance(saved.get("facts"), dict):
            return {"optional_inventory_status": "invalid"}
        return {"optional_inventory_status": "completed", **optional_summary(saved["facts"])}
    if result.exists():
        return {"optional_inventory_status": "invalid"}
    save(started, json.dumps(scope).encode())
    sync(directory)
    facts = optional_summary(platform.inventory())
    encoded = json.dumps({"scope": scope, "facts": facts}).encode()
    if len(encoded) > 16384:
        return {"optional_inventory_status": "invalid"}
    save(result, encoded)
    sync(directory)
    return {"optional_inventory_status": "completed", **facts}
