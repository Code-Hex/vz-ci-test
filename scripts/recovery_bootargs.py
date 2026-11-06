"""A reversible debug boot-argument transaction for normal and quick reboot."""
import ctypes
import kdp_registry
import hashlib
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


def boot_argument_profile(value):
    value = text(value)
    mask = debug_mask(value)
    tokens = [token for token in value.split() if token.partition('=')[0].lstrip('-') != 'debug']
    canonical = json.dumps(tokens, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return {'status': 'observed', 'debug_mask': mask, 'nondebug_token_count': len(tokens),
            'nondebug_sha256': hashlib.sha256(canonical).hexdigest()}


def decode_bootmarker_stdout(raw):
    if (type(raw) is not bytes or not raw.endswith(b'\n') or len(raw)>1024 or
            any(byte<32 or byte>126 for byte in raw[:-1])):
        raise ValueError('boot_marker_stdout_invalid')
    return raw[:-1]


def _bootmarker_nonce(nonce):
    if type(nonce) is not str or not re.fullmatch(r'[0-9a-f]{64}',nonce):
        raise ValueError('boot_marker_nonce_invalid')
    return 'vz_ci_nonce='+nonce


def _bootmarker_profile(value, mask):
    if (type(value) is not dict or set(value)!={'status','debug_mask','nondebug_token_count','nondebug_sha256'} or
            value['status']!='observed' or type(value['debug_mask']) is not type(mask) or value['debug_mask']!=mask or
            type(value['nondebug_token_count']) is not int or not 0<=value['nondebug_token_count']<=512 or
            type(value['nondebug_sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}',value['nondebug_sha256'])):
        raise ValueError('boot_marker_profile_invalid')
    return dict(value)


def checked_bootmarker_control(value, nonce, baseline_profile):
    token=_bootmarker_nonce(nonce)
    if type(value) is not dict: raise ValueError('boot_marker_control_invalid')
    if value.get('status') in ('invalid','unavailable','uncertain'):
        if set(value)!={'status'}: raise ValueError('boot_marker_control_invalid')
        return dict(value)
    baseline=_bootmarker_profile(baseline_profile,None)
    if (set(value)!={'status','marker_sha256','active_sha256','active_byte_count','full_profile','remaining_profile'} or
            value.get('status')!='observed' or value['marker_sha256']!=hashlib.sha256(token.encode()).hexdigest() or
            type(value['active_byte_count']) is not int or not len(token)<=value['active_byte_count']<=255 or
            type(value['active_sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}',value['active_sha256'])):
        raise ValueError('boot_marker_control_invalid')
    full=_bootmarker_profile(value['full_profile'],0x102000)
    remaining=_bootmarker_profile(value['remaining_profile'],0x102000)
    if (full['nondebug_token_count']!=remaining['nondebug_token_count']+1 or
            any(remaining[k]!=baseline[k] for k in ('nondebug_token_count','nondebug_sha256'))):
        raise ValueError('boot_marker_profile_mismatch')
    return dict(value)


def bootmarker_proven(value, nonce, baseline_profile):
    try: return checked_bootmarker_control(value,nonce,baseline_profile)['status']=='observed'
    except (ValueError,TypeError,KeyError): return False


def bootmarker_control(raw_stdout, nonce, baseline_profile):
    token=_bootmarker_nonce(nonce); body=decode_bootmarker_stdout(raw_stdout)
    if len(body)>255: raise ValueError('boot_marker_arguments_too_long')
    args=body.decode('ascii'); tokens=args.split()
    candidates=[i for i,t in enumerate(tokens) if t.partition('=')[0].lstrip('-')=='vz_ci_nonce']
    if len(candidates)!=1 or tokens[candidates[0]]!=token: raise ValueError('boot_marker_token_invalid')
    remaining=' '.join(t for i,t in enumerate(tokens) if i!=candidates[0])
    value={'status':'observed','marker_sha256':hashlib.sha256(token.encode()).hexdigest(),
           'active_sha256':hashlib.sha256(body).hexdigest(),'active_byte_count':len(body),
           'full_profile':boot_argument_profile(args),'remaining_profile':boot_argument_profile(remaining)}
    return checked_bootmarker_control(value,nonce,baseline_profile)


def observe_bootmarker_baseline(*, read=None):
    read=capture if read is None else read
    try:
        raw=read(['/usr/sbin/sysctl','-n','kern.bootargs'],1025,timeout=8)
        body=decode_bootmarker_stdout(raw)
        if any(t.partition(b'=')[0].lstrip(b'-')==b'vz_ci_nonce' for t in body.split()):
            raise ValueError('existing_boot_marker')
        return _bootmarker_profile(boot_argument_profile(body),None)
    except ValueError: return {'status':'invalid'}
    except (OSError,subprocess.SubprocessError): return {'status':'unavailable'}


class CaptureLimit(ValueError):
    def __init__(self, output, stderr):
        super().__init__("platform response oversized")
        self.output, self.stderr = output, stderr


def capture(argv, limit=4_000_000, timeout=8, *, capture_stderr=False, on_timeout=None):
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL, bufsize=0)
    selector = selectors.DefaultSelector()
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
        if capture_stderr: selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
        deadline, total = time.monotonic() + timeout, 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout,
                    output=bytes(buffers['stdout']) if capture_stderr else None,
                    stderr=bytes(buffers['stderr']) if capture_stderr else None)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(argv, timeout,
                    output=bytes(buffers['stdout']) if capture_stderr else None,
                    stderr=bytes(buffers['stderr']) if capture_stderr else None)
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), min(65536, limit + 1 - total))
                if not chunk:
                    selector.unregister(key.fileobj); continue
                buffers[key.data].extend(chunk[:limit-total])
                total += len(chunk)
                if total > limit:
                    if capture_stderr: raise CaptureLimit(bytes(buffers['stdout']), bytes(buffers['stderr']))
                    raise ValueError("platform response oversized")
        try:
            code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(argv, timeout,
                output=bytes(buffers['stdout']) if capture_stderr else None,
                stderr=bytes(buffers['stderr']) if capture_stderr else None) from None
        if code:
            raise subprocess.CalledProcessError(code, argv,
                output=bytes(buffers['stdout']) if capture_stderr else None,
                stderr=bytes(buffers['stderr']) if capture_stderr else None)
        return bytes(buffers['stdout'])
    except subprocess.TimeoutExpired as error:
        frozen={'timeout_seconds':error.timeout,
                'stdout':bytes(error.output) if type(error.output) is bytes else None,
                'stderr':bytes(error.stderr) if type(error.stderr) is bytes else None}
        if on_timeout is not None and child.returncode is None:
            try: on_timeout(child.pid,dict(frozen))
            except BaseException: pass
        raise
    finally:
        selector.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        child.stdout.close()
        if child.stderr is not None: child.stderr.close()


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
    "debug_boot_arg": ("(uint32_t)`debug_boot_arg", "u32"),
    "kdp_flag": ("(uint32_t)`kdp_flag", "u32"),
    "send_registered": ("`kdp_en_send_pkt != 0", "bool"),
    "receive_registered": ("`kdp_en_recv_pkt != 0", "bool"),
    "panicDebugging": ("(uint32_t)`panicDebugging", "u32"),
    "dtrace_destructive_disallow": ("(int32_t)`dtrace_destructive_disallow", "i32"),
    "coprocessor_paniclog_flush": ("(boolean_t)`coprocessor_paniclog_flush", "bool"),
    "commit_paniclog_to_nvram": ("(uint32_t)`commit_paniclog_to_nvram", "u32"),
}


def kernel_field_program(name):
    if type(name) is not str or name not in KERNEL_FIELDS: raise ValueError("kernel debug field invalid")
    expression, kind = KERNEL_FIELDS[name]
    cast, format = ("int64_t", "%lld") if kind == "i32" else ("uint64_t", "%llu")
    return ('dtrace:::ERROR { exit(1); } dtrace:::BEGIN { printf("VZKSTATE v1 ' + name + ' ' + kind + ' ' +
            format + '\\n", (' + cast + ')(' + expression + ')); exit(0); }')


def kernel_field_value(name, value):
    if type(name) is not str or name not in KERNEL_FIELDS:
        raise ValueError("kernel debug value invalid")
    kind = KERNEL_FIELDS[name][1]
    if kind == 'bool':
        if type(value) is not bool: raise ValueError("kernel debug value invalid")
    else:
        minimum, maximum = (-2147483648, 2147483647) if kind == 'i32' else (0, 0xffffffff)
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError("kernel debug value invalid")
    return value


def parse_kernel_field(name, raw):
    if type(name) is not str or name not in KERNEL_FIELDS or type(raw) is not bytes:
        raise ValueError("kernel debug value invalid")
    kind = KERNEL_FIELDS[name][1]
    prefix = ('VZKSTATE v1 ' + name + ' ' + kind + ' ').encode('ascii')
    match = re.fullmatch(re.escape(prefix) + rb'(-?[0-9]{1,10})\n\n', raw)
    if not match: raise ValueError("kernel debug value invalid")
    value = int(match.group(1))
    if match.group(1) != str(value).encode('ascii') or kind == 'bool' and value not in (0, 1):
        raise ValueError("kernel debug value invalid")
    return kernel_field_value(name, bool(value) if kind == 'bool' else value)


KERNEL_ERROR_REASONS = frozenset(('command_failed', 'timeout', 'output_limit', 'os_error', 'unknown', 'output_invalid'))


def kernel_error_summary(value):
    if (type(value) is not dict or set(value) != {'reason', 'exit_code', 'output_bytes', 'output_sha256', 'tags'} or
            type(value['reason']) is not str or value['reason'] not in KERNEL_ERROR_REASONS or
            not (value['exit_code'] is None or type(value['exit_code']) is int and -255 <= value['exit_code'] <= 255) or
            not (value['output_bytes'] is None or type(value['output_bytes']) is int and 0 <= value['output_bytes'] <= 4096) or
            not (value['output_sha256'] is None or type(value['output_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['output_sha256'])) or
            (value['output_bytes'] is None) != (value['output_sha256'] is None) or
            type(value['tags']) is not list or len(value['tags']) > 4 or
            not all(type(tag) is str and re.fullmatch('D_[A-Z0-9_]{1,40}', tag) for tag in value['tags']) or
            value['tags'] != sorted(set(value['tags']))):
        raise ValueError('kernel error invalid')
    return {**value, 'tags': list(value['tags'])}


def kernel_failure(reason, error=None, raw=None):
    output = raw if type(raw) is bytes else getattr(error, 'output', None)
    stderr = getattr(error, 'stderr', None)
    collected = type(output) is bytes or type(stderr) is bytes
    output = output if type(output) is bytes else b''
    stderr = stderr if type(stderr) is bytes else b''
    combined = (output + stderr)[:4096]
    code = getattr(error, 'returncode', 0 if type(raw) is bytes else None)
    if type(code) is not int or not -255 <= code <= 255: code = None
    tags = sorted(set(tag.decode('ascii') for tag in re.findall(rb'\[(D_[A-Z0-9_]{1,40})\]', stderr)))[:4]
    return kernel_error_summary({'reason': reason, 'exit_code': code,
        'output_bytes': len(combined) if collected else None,
        'output_sha256': hashlib.sha256(combined).hexdigest() if collected else None, 'tags': tags})


def kernel_field_state(name, *, read=None, timeout=5):
    if type(name) is not str or name not in KERNEL_FIELDS: raise ValueError("kernel debug field invalid")
    if type(timeout) is not int or timeout not in (5, 30): raise ValueError("kernel debug timeout invalid")
    read = capture if read is None else read
    raw = None
    try:
        raw = read(["/usr/sbin/dtrace", "-q", "-x", "errtags", "-n", kernel_field_program(name)], 4096, timeout=timeout, capture_stderr=True)
        return {"status": "observed", "value": parse_kernel_field(name, raw)}
    except subprocess.CalledProcessError as error:
        return {"status": "unavailable", "error": kernel_failure('command_failed', error)}
    except subprocess.TimeoutExpired as error:
        return {"status": "unavailable", "error": kernel_failure('timeout', error)}
    except CaptureLimit as error:
        return {"status": "unavailable", "error": kernel_failure('output_limit', error)}
    except OSError as error:
        return {"status": "unavailable", "error": kernel_failure('os_error', error)}
    except subprocess.SubprocessError as error:
        return {"status": "unavailable", "error": kernel_failure('unknown', error)}
    except ValueError:
        return {"status": "invalid", "error": kernel_failure('output_invalid', raw=raw)}


def kernel_debug_state(*, read=None):
    return {name: kernel_field_state(name, read=read, timeout=30 if index == 0 else 5)
            for index, name in enumerate(KERNEL_FIELDS)}


class KernelMaskInventory:
    def __init__(self, *, read=None):
        self.read = read

    def inventory(self):
        return {'kernel_debug_state': {'debug_boot_arg': kernel_field_state('debug_boot_arg', read=self.read, timeout=30)}}

    @staticmethod
    def summarize(facts):
        if type(facts) is not dict or type(facts.get('kernel_debug_state')) is not dict or set(facts['kernel_debug_state']) != {'debug_boot_arg'}:
            raise ValueError('kernel mask inventory invalid')
        state = facts['kernel_debug_state']['debug_boot_arg']
        if type(state) is not dict: raise ValueError('kernel mask inventory invalid')
        if state.get('status') == 'observed':
            if set(state) != {'status', 'value'}: raise ValueError('kernel mask inventory invalid')
            kernel_field_value('debug_boot_arg', state['value'])
        else:
            if set(state) != {'status', 'error'} or state['status'] not in ('unavailable', 'invalid'):
                raise ValueError('kernel mask inventory invalid')
            kernel_error_summary(state['error'])
        return optional_summary(facts)


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
                  "debugger_inventory_status": "unavailable", "network_inventory_status": "unavailable",
                  "registered_services": kdp_registry.snapshot()}
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
    if 'registered_services' in data:
        try:
            result['registered_services'] = kdp_registry.sanitize_snapshot(data['registered_services'])
        except (ValueError, TypeError):
            pass
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
        for name in KERNEL_FIELDS:
            value = states.get(name)
            if not isinstance(value, dict) or value.get("status") not in ("observed", "unavailable", "invalid"):
                continue
            record = {"status": value["status"]}
            number = value.get("value")
            if record["status"] == "observed":
                try:
                    record["value"] = kernel_field_value(name, number)
                except ValueError:
                    record["status"] = "invalid"
            if 'error' in value:
                try:
                    if record['status'] == 'observed': raise ValueError('kernel error invalid')
                    record['error'] = kernel_error_summary(value['error'])
                except ValueError:
                    record = {'status': 'invalid'}
            result["kernel_debug_state"][name] = record
    return result


def observe_once(directory, marker, platform, save, sync, *, current_boot_uuid):
    summarize = platform.summarize if isinstance(platform, KernelMaskInventory) else optional_summary
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
        return {"optional_inventory_status": "completed", **summarize(saved["facts"])}
    if result.exists():
        return {"optional_inventory_status": "invalid"}
    save(started, json.dumps(scope).encode())
    sync(directory)
    facts = summarize(platform.inventory())
    encoded = json.dumps({"scope": scope, "facts": facts}).encode()
    if len(encoded) > 16384:
        return {"optional_inventory_status": "invalid"}
    save(result, encoded)
    sync(directory)
    return {"optional_inventory_status": "completed", **facts}
