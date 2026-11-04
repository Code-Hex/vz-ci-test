#!/usr/bin/env python3
import json
import os
import pathlib
import plistlib
import re
import resource
import stat
import struct
import tempfile
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


ENTRIES = ('com.apple.driver.AppleEFINVRAM', 'com.apple.driver.AppleEFIRuntime')


def selected_entries(data):
    if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
        raise ValueError('unexpected_kext_schema')
    ids = [item.get('id') for item in data]
    if any(ids.count(name) > 1 for name in ENTRIES):
        raise ValueError('duplicate_entry')
    return [name for name in ENTRIES if name in ids]


def loaded_uuid(text, entry):
    pattern = re.compile(r'^\s*[0-9]+\s+[0-9]+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+' +
        re.escape(entry) + r'\s+\([^\s()]+\)\s+([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})(?:\s+<[0-9 ]*>)?\s*$')
    candidates = [line for line in text.splitlines() if entry in line.split()]
    match = pattern.fullmatch(candidates[0]) if len(candidates) == 1 else None
    return {'status': 'observed', 'uuid': match.group(1).upper()} if match else {'status': 'unavailable', 'uuid': None}


def valid_extracted(path):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 32 <= info.st_size <= 64 * 1024 * 1024:
            return False
        with path.open('rb') as source:
            magic, cpu = struct.unpack('<II', source.read(8))
        return magic == 0xfeedfacf and cpu == 0x01000007
    except (OSError, struct.error):
        return False


class SymbolCensus:
    def __init__(self, target=None):
        self.target = target
        self.candidates = []
        self.target_count = 0
        self.pending = []
        self.member = 0
        self.member_bad = set()
        self.last = None
        self.overflow = False

    def feed(self, line):
        match = re.match(r'^\s*([0-9a-fA-F]+)\s+[Tt]\s+(\S+)\s*$', line)
        if not match:
            if line.strip().endswith(':') and not line[:1].isspace():
                self.pending = []
                self.last = None
                self.member += 1
            return
        address, name = int(match.group(1), 16), match.group(2)
        if self.last is not None and address < self.last:
            self.member_bad.add(self.member)
        if self.last is not None and address > self.last:
            for candidate in self.pending:
                candidate['end'] = address
            self.pending = []
        if self.last == address:
            for candidate in self.pending:
                candidate['ambiguous'] = True
        wanted = bool(self.target.fullmatch(name)) if self.target else bool(SYMBOL.match(line) and INTEREST.search(name))
        if wanted:
            self.target_count += 1
            if len(self.candidates) < 4096:
                candidate = {'name': name, 'start': address, 'end': None, 'member': self.member,
                             'ambiguous': self.last == address}
                self.candidates.append(candidate)
                self.pending.append(candidate)
            else:
                self.overflow = True
        self.last = address

    def finish(self):
        counts = {}
        for candidate in self.candidates:
            counts[candidate['name']] = counts.get(candidate['name'], 0) + 1
        for candidate in self.candidates:
            candidate['ambiguous'] |= (counts[candidate['name']] != 1 or candidate['member'] in self.member_bad or candidate['end'] is None)
        def rank(candidate):
            name = candidate['name'].lower()
            return (0 if 'setvariable' in name or 'write' in name else 1 if 'sync' in name else 2, name)
        return {'target_count': self.target_count, 'candidates': sorted(self.candidates, key=rank)[:24],
                'census_overflow': self.overflow}


def nm_census(argv, deadline):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    census = SymbolCensus()
    buffer = b''
    total = 0
    status = 'ok'
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(max(remaining, 0)):
                status = 'deadline'
                break
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk: break
            total += len(chunk)
            if total > 256 * 1024 * 1024:
                status = 'nm_output_limit'
                break
            buffer += chunk
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                if len(line) > 8192:
                    status = 'nm_line_limit'
                    break
                census.feed(line.decode('utf-8', 'replace'))
            if status != 'ok': break
            if len(buffer) > 8192:
                status = 'nm_line_limit'
                break
        if status == 'ok' and buffer: census.feed(buffer.decode('utf-8', 'replace'))
        if status != 'ok': process.kill()
        try: code = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            status = 'deadline'
        if status == 'ok' and code != 0: status = 'tool_error'
        return status, census.finish()
    finally:
        selector.close()
        process.stdout.close()


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


def command(argv, max_bytes, timeout=20, deadline=None, file_limit=None):
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            preexec_fn=limit if file_limit is not None else None)
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
    private = output.parent / 'private'
    private.mkdir(mode=0o700, exist_ok=True)
    if private.is_symlink() or not private.is_dir():
        print(json.dumps({'event': 'private_directory', 'status': 'invalid'}), flush=True)
        return 1
    os.chmod(private, 0o700)
    ipsw = os.environ.get('NVRAM_IPSW', '')
    expected_ipsw = output.parent / 'bin' / 'ipsw'
    config = private / 'ipsw-empty.yml'
    extraction = {'status': 'pending', 'source': 'BootKernelExtensions.kc',
                  'image_kind': 'reconstructed', 'runtime_match': 'not_verified', 'entries': []}
    result['extraction'] = extraction
    save()
    temp = tempfile.TemporaryDirectory(prefix='nvram-extract-', dir=private)
    extracted = []
    try:
        if (not os.path.isabs(ipsw) or pathlib.Path(ipsw) != expected_ipsw or
                not os.path.isfile(ipsw) or os.path.islink(ipsw)):
            extraction['status'] = 'tool_unavailable'
        else:
            if not config.exists():
                fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            if config.is_symlink() or not config.is_file() or config.stat().st_size != 0:
                extraction['status'] = 'config_invalid'
            else:
                status, version = command([ipsw, '--config', str(config), 'version'], 4096, 5, deadline)
                if status != 'ok' or not re.search(r'Version:\s*3\.1\.730(?:,|\s|$)', version):
                    extraction['status'] = 'tool_version_unverified'
                else:
                    status, data = command([ipsw, '--config', str(config), 'kernel', 'kexts', BINARIES[3],
                                            '--arch', 'x86_64', '--json'], 8 * 1024 * 1024, 40, deadline)
                    if status != 'ok':
                        extraction['status'] = 'list_' + status
                    else:
                        try:
                            entries = selected_entries(json.loads(data))
                        except (ValueError, json.JSONDecodeError):
                            entries = []
                            extraction['status'] = 'list_invalid'
                        else:
                            extraction['status'] = 'observed' if entries else 'no_matching_entry'
                        for name in entries:
                            unit = {'entry': name, 'status': 'pending'}
                            extraction['entries'].append(unit)
                            save()
                            directory = pathlib.Path(temp.name) / name
                            directory.mkdir(mode=0o700)
                            status, _ = command([ipsw, '--config', str(config), 'macho', 'info', BINARIES[3],
                                '--arch', 'x86_64', '--fileset-entry', name, '--extract-fileset-entry',
                                '--output', str(directory)], 65536, 40, deadline, 64 * 1024 * 1024)
                            candidate = directory / name
                            if status != 'ok': unit['status'] = 'extract_' + status
                            elif not valid_extracted(candidate): unit['status'] = 'extract_invalid'
                            else:
                                unit['status'] = 'extracted'
                                uuid_status, uuid_output = command(['/usr/bin/xcrun', 'dwarfdump', '--uuid', str(candidate)], 4096, 10, deadline)
                                found = re.search(r'UUID: ([0-9A-Fa-f-]{36}) \(x86_64\)', uuid_output) if uuid_status == 'ok' else None
                                unit['image_uuid'] = found.group(1).upper() if found else None
                                loaded_status, loaded_text = command(['/usr/sbin/kextstat', '-l', '-b', name], 32768, 10, deadline)
                                unit['loaded_image'] = loaded_uuid(loaded_text, name) if loaded_status == 'ok' else {'status': loaded_status, 'uuid': None}
                                loaded = unit['loaded_image']['uuid']
                                unit['runtime_match'] = ('verified' if loaded == unit['image_uuid'] else 'mismatch') if loaded and unit['image_uuid'] else 'not_verified'
                                extracted.append((str(candidate), name))
                            save()
    except (OSError, subprocess.SubprocessError):
        extraction['status'] = 'unavailable'
    if (len(extraction['entries']) == len(ENTRIES) and
            all(unit.get('runtime_match') == 'verified' for unit in extraction['entries'])):
        extraction['runtime_match'] = result['binary_loaded_status'] = 'verified'
    save()
    sources = [(path, None) for path in BINARIES]
    sources = [(path, entry) for path, entry in extracted] + sources
    for path, entry in sources:
        item = {'path': path if entry is None else 'reconstructed:' + entry, 'functions': [], 'status': 'pending'}
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
            status, census = nm_census(['/usr/bin/xcrun', 'nm', '-n', path], deadline)
            item['target_count'] = census['target_count']
            item['target_count_complete'] = status == 'ok'
            item['status'] = status if status != 'ok' else ('unsupported' if not census['target_count'] else
                'target_census_limit' if census['census_overflow'] else
                'target_count_limited' if census['target_count'] > 24 else 'observed')
            save()
            candidates = census['candidates'] if status == 'ok' and not census['census_overflow'] else []
            for candidate in candidates:
                name = candidate['name']
                function = {'symbol': name, 'status': 'pending', 'instructions': []}
                item['functions'].append(function)
                save()
                if time.monotonic() >= deadline:
                    function['status'] = 'deadline'
                    break
                if candidate['ambiguous']:
                    function['status'] = 'unsupported'
                    continue
                start, end = candidate['start'], candidate['end']
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
    temp.cleanup()
    print(json.dumps({'event': 'complete', 'status': 'saved', 'path': str(output)}), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
