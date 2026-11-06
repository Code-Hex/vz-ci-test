"""Read one panic property and identify a run-specific panic without printing it."""
import ctypes
import hashlib
import re

from nonce_usdt import ProbeSpec

MAX_RAW = 16 * 768
KERNEL_UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
HEADER = re.compile(rb'^panic\(cpu [0-9]+(?: caller (?:0x)?[0-9a-fA-F]+)?\): dtrace: panic action at probe pid[1-9][0-9]*:[^:\r\n]+:vz_nonce_([0-9a-f]{64}):entry \(ecb (?:0x)?[0-9a-fA-F]+\)(?:\r?\n|$)')
UUID = re.compile(rb'(?im)^Kernel UUID:[ \t]*([0-9a-f-]+)[ \t]*\r?\n')
UUID_PREFIX = re.compile(rb'(?im)^Kernel UUID:')
PANIC_PREFIX = re.compile(rb'(?m)^panic\(')


def unpack_a(raw):
    if len(raw) % 7 or len(raw) > MAX_RAW:
        raise ValueError('invalid packed length')
    out = bytearray()
    for offset in range(0, len(raw), 7):
        bits = int.from_bytes(raw[offset:offset + 7], 'little')
        out.extend((bits >> (7 * i)) & 0x7f for i in range(8))
    return bytes(out)


def classify_candidates(candidates, nonce):
    if not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{64}', nonce):
        raise ValueError('invalid nonce')
    return _classify_candidates(candidates, nonce, HEADER)


def _classify_candidates(candidates, expected, header):
    recognized = []
    for encoding, data in candidates:
        match = header.match(data)
        if not match:
            if data.startswith(b'panic(') and b'\0' not in data:
                recognized.append({'status': 'truncated', 'encoding': encoding, 'terminator_present': False})
            continue
        end = data.find(b'\0')
        text = data if end < 0 else data[:end]
        uuids = UUID.findall(text + (b'\n' if end >= 0 else b''))
        if len(PANIC_PREFIX.findall(data)) != 1 or len(UUID_PREFIX.findall(data)) > 1:
            status = 'ambiguous'
        elif match.group(1).decode('ascii') != expected:
            status = 'nonce_missing'
        elif not uuids:
            status = 'uuid_missing'
        elif len(uuids) != 1 or uuids[0].decode('ascii').upper() != KERNEL_UUID:
            status = 'uuid_mismatch'
        else:
            status = 'fresh_fragment'
        recognized.append({'status': status, 'encoding': encoding, 'terminator_present': end >= 0})
    if len(recognized) > 1:
        selected = {'status': 'ambiguous', 'encoding': None, 'terminator_present': None}
    elif recognized:
        selected = recognized[0]
    else:
        selected = {'status': 'unrecognized', 'encoding': None, 'terminator_present': None}
    selected.update(freshness='verified' if selected['status'] == 'fresh_fragment' else 'unverified',
                    completeness='unknown', packed_tail_bytes=0)
    return selected


def classify(raw, nonce):
    if not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{64}', nonce):
        raise ValueError('invalid nonce')
    return _classify(raw, nonce, HEADER)


def classify_usdt(raw, nonce, helper_pid):
    probe = ProbeSpec(nonce).bind(helper_pid)
    selector = probe.selector.encode('ascii')
    header = re.compile(rb'^panic\(cpu [0-9]+(?: caller (?:0x)?[0-9a-fA-F]+)?\): dtrace: panic action at probe (' +
                        re.escape(selector) + rb') \(ecb (?:0x)?[0-9a-fA-F]+\)(?:\r?\n|$)')
    return _classify(raw, probe.selector, header)


def syscall_marker(nonce, helper_pid):
    if type(nonce) is not str or not re.fullmatch(r'[0-9a-f]{64}', nonce):
        raise ValueError('invalid nonce')
    if type(helper_pid) is not int or not 0 < helper_pid < 2**31:
        raise ValueError('invalid helper pid')
    return 'vz-reboot-panic:' + nonce + ':' + str(helper_pid)


def classify_syscall(raw, nonce, helper_pid):
    marker = syscall_marker(nonce, helper_pid)
    header = re.compile(rb'^panic\(cpu [0-9]+(?: caller (?:0x)?[0-9a-fA-F]+)?\): userspace panic: (' +
                        re.escape(marker.encode('ascii')) + rb')(?:\r?\n|$)')
    return _classify(raw, marker, header)


def classify_begin(raw, nonce, active_bootargs_sha256):
    if type(nonce) is not str or not re.fullmatch(r'[0-9a-f]{64}', nonce):
        raise ValueError('invalid nonce')
    if type(active_bootargs_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', active_bootargs_sha256):
        raise ValueError('invalid boot arguments digest')
    header = re.compile(rb'^panic\(cpu [0-9]+(?: caller (?:0x)?[0-9a-fA-F]+)?\): dtrace: panic action at probe '
                        rb'(dtrace:::BEGIN) \(ecb (?:0x)?[0-9a-fA-F]+\)(?:\r?\n|$)')
    result = _classify(raw, 'dtrace:::BEGIN', header)
    if result['status'] != 'fresh_fragment':
        return result
    candidate = raw if result['encoding'] == 'raw' else unpack_a(raw[:len(raw) - len(raw) % 7])
    end = candidate.find(b'\0')
    text = candidate if end < 0 else candidate[:end]
    prefixes = re.findall(rb'(?im)(?:^|\x00)Boot args:', candidate)
    lines = re.findall(rb'(?m)^Boot args: ([ -~]{0,255})\r?\n', text)
    if len(prefixes) != 1:
        status = 'ambiguous' if len(prefixes) > 1 else 'bootargs_missing'
    elif len(lines) != 1:
        status = 'bootargs_invalid'
    else:
        body = lines[0]
        tokens = body.split()
        markers = [token for token in tokens if token.partition(b'=')[0].lstrip(b'-') == b'vz_ci_nonce']
        if markers != [('vz_ci_nonce=' + nonce).encode('ascii')]:
            status = 'nonce_missing'
        elif hashlib.sha256(body).hexdigest() != active_bootargs_sha256:
            status = 'bootargs_mismatch'
        else:
            return result
    result.update(status=status, freshness='unverified')
    return result


def _classify(raw, expected, header):
    if not isinstance(raw, bytes):
        raise TypeError('raw must be bytes')
    if not raw or len(raw) > MAX_RAW:
        return {'status': 'empty' if not raw else 'oversized', 'encoding': None,
                'freshness': 'unverified', 'completeness': 'unknown',
                'terminator_present': None, 'packed_tail_bytes': 0}
    candidates = [('raw', raw)]
    packed_length = len(raw) - len(raw) % 7
    if packed_length:
        candidates.append(('packA', unpack_a(raw[:packed_length])))
    result = _classify_candidates(candidates, expected, header)
    if result['encoding'] == 'packA':
        result['packed_tail_bytes'] = len(raw) % 7
    return result


def read_panic_info():
    """Return (status, bytes-or-None); no property data is logged or written."""
    try:
        io = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
        cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    except OSError:
        return 'unavailable', None
    io.IORegistryEntryFromPath.argtypes = [ctypes.c_uint, ctypes.c_char_p]
    io.IORegistryEntryFromPath.restype = ctypes.c_uint
    io.IORegistryEntryCreateCFProperty.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
    io.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p
    io.IOObjectRelease.argtypes = [ctypes.c_uint]
    io.IOObjectRelease.restype = ctypes.c_int
    cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFGetTypeID.argtypes = [ctypes.c_void_p]
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFDataGetTypeID.argtypes = []
    cf.CFDataGetTypeID.restype = ctypes.c_ulong
    cf.CFDataGetLength.argtypes = [ctypes.c_void_p]
    cf.CFDataGetLength.restype = ctypes.c_long
    cf.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
    cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
    cf.CFRelease.argtypes = [ctypes.c_void_p]
    cf.CFRelease.restype = None
    entry = io.IORegistryEntryFromPath(0, b'IODeviceTree:/options')
    if not entry:
        return 'unavailable', None
    key = value = None
    try:
        key = cf.CFStringCreateWithCString(None, b'aapl,panic-info', 0x08000100)
        if not key:
            return 'unavailable', None
        value = io.IORegistryEntryCreateCFProperty(entry, key, None, 0)
        if not value:
            return 'unavailable', None
        if cf.CFGetTypeID(value) != cf.CFDataGetTypeID():
            return 'unexpected_type', None
        size = cf.CFDataGetLength(value)
        if size < 0 or size > MAX_RAW:
            return 'oversized', None
        if not size:
            return 'empty', b''
        ptr = cf.CFDataGetBytePtr(value)
        if not ptr:
            return 'unavailable', None
        return 'observed', ctypes.string_at(ptr, size)
    finally:
        if value: cf.CFRelease(value)
        if key: cf.CFRelease(key)
        io.IOObjectRelease(entry)
