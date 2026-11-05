"""Read four registered-service classes and one fixed Boolean property."""
import ctypes
import platform
import re
import sys


CLASSES = ('IOPlatformExpertDevice', 'IOKernelDebugger', 'IOKDP', 'IONVRAMController')
SCOPE = 'current_registered_services_not_polled_io_proof'


def decode_class(raw):
    if not isinstance(raw, bytes) or b'\x00' not in raw or len(raw) > 128:
        return None
    name = raw.split(b'\x00', 1)[0]
    return name.decode('ascii') if re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_.$:-]{0,126}', name) else None


def query_result(status, returncode, nodes):
    return {'status': status, 'returncode': returncode,
            'count': len(nodes) if status == 'observed' else None, 'nodes': nodes}


def _load():
    io = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
    cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    handle, pointer = ctypes.c_uint32, ctypes.c_void_p
    boolean = ctypes.c_uint if platform.machine() == 'x86_64' else ctypes.c_int
    for name, arguments, result in (
            ('IOServiceMatching', [ctypes.c_char_p], pointer),
            ('IOServiceGetMatchingServices', [handle, pointer, ctypes.POINTER(handle)], ctypes.c_int),
            ('IOIteratorNext', [handle], handle),
            ('IOIteratorIsValid', [handle], boolean),
            ('IOObjectGetClass', [handle, ctypes.POINTER(ctypes.c_char)], ctypes.c_int),
            ('IORegistryEntryGetParentEntry', [handle, ctypes.c_char_p, ctypes.POINTER(handle)], ctypes.c_int),
            ('IORegistryEntryCreateCFProperty', [handle, pointer, pointer, ctypes.c_uint32], pointer),
            ('IOObjectRelease', [handle], ctypes.c_int)):
        function = getattr(io, name)
        function.argtypes, function.restype = arguments, result
    for name, arguments, result in (
            ('CFStringCreateWithCString', [pointer, ctypes.c_char_p, ctypes.c_uint32], pointer),
            ('CFGetTypeID', [pointer], ctypes.c_ulong),
            ('CFBooleanGetTypeID', [], ctypes.c_ulong),
            ('CFBooleanGetValue', [pointer], ctypes.c_ubyte),
            ('CFRelease', [pointer], None)):
        function = getattr(cf, name)
        function.argtypes, function.restype = arguments, result
    return io, cf


def _class(io, entry):
    buffer = ctypes.create_string_buffer(128)
    code = io.IOObjectGetClass(entry, buffer)
    return (decode_class(buffer.raw) if code == 0 else None), code


def _enabled(io, cf, entry, key):
    value = io.IORegistryEntryCreateCFProperty(entry, key, None, 0)
    if not value:
        return {'status': 'unavailable', 'value': None}
    try:
        if cf.CFGetTypeID(value) != cf.CFBooleanGetTypeID():
            return {'status': 'noncanonical', 'value': None}
        return {'status': 'observed', 'value': bool(cf.CFBooleanGetValue(value))}
    finally:
        cf.CFRelease(value)


def _parents(io, entry):
    names, owned = [], 0
    try:
        for _ in range(8):
            parent = ctypes.c_uint32()
            code = io.IORegistryEntryGetParentEntry(owned or entry, b'IOService', ctypes.byref(parent))
            if code != 0 or not parent.value:
                if parent.value: io.IOObjectRelease(parent.value)
                return names, 'stopped', code
            if owned: io.IOObjectRelease(owned)
            owned = parent.value
            name, code = _class(io, owned)
            if name is None:
                return names, 'error' if code else 'noncanonical', code
            names.append(name)
        return names, 'bounded', 0
    finally:
        if owned: io.IOObjectRelease(owned)


def _query(io, cf, key, name):
    matching = io.IOServiceMatching(name.encode('ascii'))
    if not matching:
        return query_result('unavailable', None, [])
    iterator, nodes = ctypes.c_uint32(), []
    # GetMatchingServices consumes matching on success and failure.
    code = io.IOServiceGetMatchingServices(0, matching, ctypes.byref(iterator))
    try:
        if code != 0:
            return query_result('error', code, nodes)
        if not iterator.value:
            return query_result('observed', code, nodes)
        while True:
            service = io.IOIteratorNext(iterator.value)
            if not service:
                status = 'observed' if io.IOIteratorIsValid(iterator.value) else 'invalid_iterator'
                return query_result(status, code, nodes)
            try:
                if len(nodes) == 64:
                    status = 'truncated' if io.IOIteratorIsValid(iterator.value) else 'invalid_iterator'
                    return query_result(status, code, nodes)
                classname, class_code = _class(io, service)
                parents, parent_status, parent_code = _parents(io, service)
                nodes.append({'class': classname, 'class_returncode': class_code, 'parents': parents,
                              'parent_status': parent_status, 'parent_returncode': parent_code,
                              'controller_enabled': _enabled(io, cf, service, key)})
            finally:
                io.IOObjectRelease(service)
    finally:
        if iterator.value: io.IOObjectRelease(iterator.value)


def snapshot():
    result = {'scope': SCOPE, 'queries': {name: query_result('unavailable', None, []) for name in CLASSES}}
    if sys.platform != 'darwin':
        return result
    key = None
    try:
        io, cf = _load()
        key = cf.CFStringCreateWithCString(None, b'IOControllerEnabled', 0x08000100)
        if not key:
            return result
        for name in CLASSES:
            result['queries'][name] = _query(io, cf, key, name)
    except (OSError, AttributeError, ValueError):
        pass
    finally:
        if key: cf.CFRelease(key)
    return result
