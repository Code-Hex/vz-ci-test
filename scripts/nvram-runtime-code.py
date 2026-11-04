#!/usr/bin/env python3
import json
import os
import pathlib
import plistlib
import re
import selectors
import subprocess
import sys
import time

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
BINARIES = (
    '/System/Library/Kernels/kernel',
    '/System/Library/Extensions/AppleEFINVRAM.kext/Contents/MacOS/AppleEFINVRAM',
    '/System/Library/Extensions/AppleEFIRuntime.kext/Contents/MacOS/AppleEFIRuntime',
    '/System/Library/KernelCollections/BootKernelExtensions.kc',
    '/System/Library/KernelCollections/SystemKernelExtensions.kc',
    '/Library/KernelCollections/AuxiliaryKernelExtensions.kc',
)
PLISTS = (
    '/Library/Preferences/SystemConfiguration/com.apple.Boot.plist',
    '/System/Library/CoreServices/com.apple.Boot.plist',
)
SYMBOL = re.compile(r'^\s*[0-9a-fA-F]+\s+[Tt]\s+(__ZNK?(?:13AppleEFINVRAM|15AppleEFIRuntime)[A-Za-z0-9_]+)\s*$')
INTEREST = re.compile(r'sync|set|write|start|register|variable', re.I)


def select_symbols(lines):
    result = []
    for line in lines:
        match = SYMBOL.match(line)
        if match and INTEREST.search(match.group(1)) and match.group(1) not in result:
            result.append(match.group(1))
    return result


def function_instructions(text, name, start, end):
    heading = re.compile(r'^\s*(?:([0-9a-fA-F]+)\s+<)?' + re.escape(name) + r'(?:>)?:\s*$')
    another = re.compile(r'^\s*(?:[0-9a-fA-F]+\s+<[^>]+>|[A-Za-z_][A-Za-z0-9_]*)[:]{1}\s*$')
    instruction = re.compile(r'^\s*([0-9a-fA-F]+):\s+\S')
    active = False
    found = False
    out = []
    previous = -1
    for line in text.splitlines():
        h = heading.match(line)
        if h:
            if found or (h.group(1) is not None and int(h.group(1), 16) != start): return []
            found = active = True
            continue
        if active and another.match(line): break
        match = instruction.match(line)
        if active and match:
            address = int(match.group(1), 16)
            if not start <= address < end or address <= previous: return []
            previous = address
            out.append(line)
    return out if found and out and int(instruction.match(out[0]).group(1), 16) == start else []


def symbol_bounds(text, selected):
    entries = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-fA-F]+)\s+[Tt]\s+(\S+)\s*$', line)
        if match: entries.append((int(match.group(1), 16), match.group(2)))
    result = {}
    for name in selected:
        addresses = [address for address, symbol in entries if symbol == name]
        if len(addresses) != 1: continue
        start = addresses[0]
        if sum(address == start for address, _ in entries) != 1: continue
        later = [address for address, _ in entries if address > start]
        if later: result[name] = (start, min(later))
    return result


def type_name(value):
    if isinstance(value, dict): return 'dictionary'
    if isinstance(value, list): return 'array'
    if isinstance(value, str): return 'string'
    if isinstance(value, bool): return 'boolean'
    if isinstance(value, (int, float)): return 'number'
    if isinstance(value, bytes): return 'data'
    return 'other'


def plist_summary(value):
    flags = value.get('Kernel Flags') if isinstance(value, dict) else None
    return {'status': 'observed', 'root_type': type_name(value),
            'kernel_flags_type': type_name(flags) if flags is not None else 'absent',
            'debug_present': bool(re.search(r'(?:^|\s)debug=', flags)) if isinstance(flags, str) else None}


def command(argv, max_bytes, timeout=20, deadline=None):
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = min(time.monotonic() + timeout, deadline or float("inf"))
    status = 'ok'
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = 'timeout'
                break
            events = selector.select(remaining)
            if not events:
                status = 'timeout'
                break
            chunk = os.read(proc.stdout.fileno(), min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                status = 'oversize'
                break
        if status != 'ok': proc.kill()
        try:
            code = proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait(timeout=2)
            status = 'timeout'
        if status == 'ok' and code != 0: status = 'tool_error'
        return status, data.decode('utf-8', 'replace') if status == 'ok' else ''
    finally:
        selector.close()
        proc.stdout.close()


def guarded():
    env = os.environ
    if (len(sys.argv) != 1 or sys.platform != 'darwin' or os.uname().machine != 'x86_64' or
        any(env.get(k) != v for k, v in {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'Code-Hex/vz-ci-test',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'RUNNER_ENVIRONMENT': 'github-hosted'}.items()) or
        not re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')) or
        not re.fullmatch(r'[1-9][0-9]{0,4}', env.get('GITHUB_RUN_ATTEMPT', '')) or
        not re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', ''))):
        return False
    status, text = command(['/usr/sbin/sysctl', '-n', 'kern.uuid'], 1024, 5)
    if status != 'ok' or text.strip() != UUID: return False
    status, text = command(['/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present'], 1024, 5)
    if status != 'ok' or text.strip() != '1': return False
    status, text = command(['/usr/bin/xcrun', 'dwarfdump', '--uuid', BINARIES[0]], 4096, 10)
    return status == 'ok' and bool(re.search(r'UUID: ' + UUID + r' \(x86_64\)', text))


def main():
    if not guarded():
        print(json.dumps({'event': 'guard', 'status': 'rejected'}), flush=True)
        return 1
    output = pathlib.Path(os.environ['RUNNER_TEMP']) / 'debug' / 'nvram-runtime-code.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 180
    result = {'kernel_uuid': UUID, 'binary_loaded_status': 'not_verified',
              'plists': [], 'preboot': {'status': 'unavailable', 'plists': []}, 'binaries': []}
    def save():
        encoded = json.dumps(result, separators=(',', ':')) + '\n'
        if len(encoded.encode()) > 2 * 1024 * 1024:
            raise ValueError('artifact_limit')
        temporary = output.with_suffix('.tmp')
        temporary.write_text(encoded)
        temporary.replace(output)

    save()
    for path in PLISTS:
        item = {'path': path}
        if time.monotonic() >= deadline:
            item['status'] = 'deadline'
            result['plists'].append(item)
            save()
            break
        try:
            with open(path, 'rb') as f:
                data = f.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024: item['status'] = 'oversize'
            else: item.update(plist_summary(plistlib.loads(data)))
        except FileNotFoundError: item['status'] = 'absent'
        except (OSError, ValueError, plistlib.InvalidFileException): item['status'] = 'unavailable'
        result['plists'].append(item)
        save()
    try:
        with os.scandir('/System/Volumes/Preboot') as entries:
            volume_ids = []
            for entry in entries:
                if time.monotonic() >= deadline:
                    result['preboot']['status'] = 'deadline'
                    break
                if re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', entry.name):
                    volume_ids.append(entry.name)
                    if len(volume_ids) > 64:
                        break
        if result['preboot']['status'] != 'deadline':
            result['preboot']['status'] = 'oversize' if len(volume_ids) > 64 else 'observed'
        if len(volume_ids) <= 64 and result['preboot']['status'] != 'deadline':
            for volume_id in volume_ids:
                for relative in ('Library/Preferences/SystemConfiguration/com.apple.Boot.plist',
                                 'System/Library/CoreServices/com.apple.Boot.plist'):
                    if time.monotonic() >= deadline:
                        result['preboot']['status'] = 'deadline'
                        break
                    path = pathlib.Path('/System/Volumes/Preboot') / volume_id / relative
                    try:
                        with path.open('rb') as f: data = f.read(1024 * 1024 + 1)
                        summary = {'status': 'oversize'} if len(data) > 1024 * 1024 else plist_summary(plistlib.loads(data))
                    except FileNotFoundError: summary = {'status': 'absent'}
                    except (OSError, ValueError, plistlib.InvalidFileException): summary = {'status': 'unavailable'}
                    result['preboot']['plists'].append(summary)
                    save()
                if result['preboot']['status'] == 'deadline': break
    except OSError:
        pass
    save()
    for path in BINARIES:
        item = {'path': path, 'functions': [], 'status': 'pending'}
        result['binaries'].append(item)
        save()
        if time.monotonic() >= deadline:
            item['status'] = 'deadline'
            save()
            break
        if not os.path.isfile(path):
            item['status'] = 'absent'
            save()
            continue
        try:
            status, out = command(['/usr/bin/xcrun', 'nm', '-n', path], 32 * 1024 * 1024, 35, deadline)
            names = select_symbols(out.splitlines()) if status == 'ok' else []
            item['status'] = status if status != 'ok' else ('observed' if names else 'unsupported')
            bounds = symbol_bounds(out, names) if status == 'ok' else {}
            save()
            if len(names) > 24:
                item['status'] = 'oversize'
                names = []
            for name in names:
                function = {'symbol': name, 'status': 'pending', 'instructions': []}
                item['functions'].append(function)
                save()
                if time.monotonic() >= deadline:
                    function['status'] = 'deadline'
                    break
                if name not in bounds:
                    function['status'] = 'unsupported'
                    continue
                start, end = bounds[name]
                status, disassembly = command(['/usr/bin/xcrun', 'llvm-objdump', '--macho', '--arch=x86_64', '--disassemble',
                    '--no-show-raw-insn', '--dis-symname', name, path], 64000, 15, deadline)
                lines = function_instructions(disassembly, name, start, end) if status == 'ok' else []
                function['status'] = status if status != 'ok' else ('observed' if lines else 'unsupported')
                function['instructions'] = lines
                try:
                    save()
                except ValueError:
                    function['instructions'] = []
                    function['status'] = 'artifact_limit'
                    save()
                    break
        except (OSError, subprocess.SubprocessError): item['status'] = 'unavailable'
        save()
    save()
    print(json.dumps({'event': 'complete', 'status': 'saved', 'path': str(output)}), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
