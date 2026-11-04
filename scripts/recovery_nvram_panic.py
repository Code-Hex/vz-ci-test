"""Read one panic property and identify a run-specific panic without printing it."""
import ctypes
import re

MAX_RAW = 16 * 768
KERNEL_UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
HEADER = re.compile(rb'^panic\(cpu [0-9]+(?: caller (?:0x)?[0-9a-fA-F]+)?\): dtrace: panic action at probe pid[1-9][0-9]*:[^:\r\n]+:vz_nonce_([0-9a-f]{64}):entry \(ecb (?:0x)?[0-9a-fA-F]+\)(?:\r?\n|$)')
UUID = re.compile(rb'(?im)^Kernel UUID:[ \t]*([0-9a-f-]+)[ \t]*\r?$')


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
    recognized = []
    for encoding, data in candidates:
        match = HEADER.match(data)
        if not match:
            if data.startswith(b'panic(') and b'\0' not in data:
                recognized.append({'status': 'truncated', 'encoding': encoding, 'completeness': 'unknown'})
            continue
        end = data.find(b'\0')
        text = data if end < 0 else data[:end]
        uuids = UUID.findall(text)
        if match.group(1).decode('ascii') != nonce:
            status = 'nonce_missing'
        elif end < 0:
            status = 'truncated'
        elif len(data) - end - 1 > (7 if encoding == 'packA' else 0):
            status = 'truncated'
        elif not uuids:
            status = 'uuid_missing'
        elif len(uuids) != 1 or uuids[0].decode('ascii').upper() != KERNEL_UUID:
            status = 'uuid_mismatch'
        else:
            status = 'verified'
        recognized.append({'status': status, 'encoding': encoding, 'completeness': 'unknown'})
    if len(recognized) > 1:
        return {'status': 'ambiguous', 'encoding': None, 'completeness': 'unknown'}
    return recognized[0] if recognized else {'status': 'unrecognized', 'encoding': None, 'completeness': 'unknown'}


def classify(raw, nonce):
    if not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{64}', nonce):
        raise ValueError('invalid nonce')
    if not isinstance(raw, bytes):
        raise TypeError('raw must be bytes')
    if not raw:
        return {'status': 'empty', 'encoding': None, 'completeness': 'unknown'}
    if len(raw) > MAX_RAW:
        return {'status': 'oversized', 'encoding': None, 'completeness': 'unknown'}
    candidates = [('raw', raw)]
    # A platform may truncate after any byte, so inspect the complete packed prefix.
    packed_length = len(raw) - len(raw) % 7
    if packed_length:
        candidates.append(('packA', unpack_a(raw[:packed_length])))
    result = classify_candidates(candidates, nonce)
    if result['encoding'] == 'packA' and len(raw) % 7:
        result['status'] = 'truncated'
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
