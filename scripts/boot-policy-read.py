#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import plistlib
import re
import stat
import subprocess
import sys
import time

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
ROOTS = ('/Library/LaunchDaemons', '/Library/LaunchAgents', '/Library/StartupItems', '/private/etc')
ALLOWED = ('/Library/PrivilegedHelperTools', '/Library/Application Support/Veertu', '/usr/local/bin')


def safe_open(path, directory=False):
    path = pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid_path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2 or directory:
                flags |= os.O_DIRECTORY
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def facts(path, data):
    lower = data.lower()
    return {'basename': path.name, 'sha256': hashlib.sha256(data).hexdigest(),
            'boot_args_literal': b'boot-args' in lower,
            'nvram_literal': b'nvram' in lower, 'debug_literal': b'debug=' in lower}


def candidates(data, allowed):
    try:
        value = plistlib.loads(data)
    except (ValueError, plistlib.InvalidFileException, RecursionError, OverflowError):
        return None
    if not isinstance(value, dict):
        return None
    items = [value.get('Program')]
    args = value.get('ProgramArguments')
    if isinstance(args, list):
        items.extend(args[:128])
    result = []
    roots = [pathlib.Path(root) for root in allowed]
    for item in items:
        if not isinstance(item, str):
            continue
        path = pathlib.Path(item)
        if path.is_absolute() and '..' not in path.parts and any(path != root and root in path.parents for root in roots):
            result.append(path)
    return {'paths': result, 'arguments_truncated': isinstance(args, list) and len(args) > 128}


def inventory(roots, allowed, deadline, rc_root=None):
    result = {'records': [], 'incomplete': [], 'files_read': 0, 'files_considered': 0, 'bytes_read': 0, 'candidate_count': 0}
    def incomplete(reason):
        if reason not in result['incomplete']:
            result['incomplete'].append(reason)

    def read_file(path):
        if time.monotonic() >= deadline:
            incomplete('deadline'); return None
        if result['files_considered'] >= 128:
            incomplete('file_limit'); return None
        result['files_considered'] += 1
        try:
            fd = safe_open(path)
            with os.fdopen(fd, 'rb') as stream:
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode):
                    incomplete('not_regular'); return None
                if st.st_size > 1024 * 1024:
                    incomplete('oversize'); return None
                if result['bytes_read'] + st.st_size > 4 * 1024 * 1024:
                    incomplete('byte_limit'); return None
                data = stream.read(st.st_size)
                after = os.fstat(stream.fileno())
            result['bytes_read'] += len(data)
            if len(data) != st.st_size or after.st_size != st.st_size or after.st_mtime_ns != st.st_mtime_ns:
                incomplete('file_changed'); return None
            result['files_read'] += 1
            result['records'].append(facts(path, data))
            return data
        except (OSError, ValueError):
            incomplete('unavailable'); return None

    queue = [(pathlib.Path(root), pathlib.Path(root) == rc_root) for root in roots]
    pending = []
    visited = set()
    entries_seen = 0
    while queue:
        if time.monotonic() >= deadline:
            incomplete('deadline'); break
        directory, only_rc = queue.pop(0)
        try:
            fd = safe_open(directory, directory=True)
            try:
                with os.scandir(fd) as entries:
                    for entry in entries:
                        entries_seen += 1
                        if entries_seen > 1024 or time.monotonic() >= deadline:
                            incomplete('entry_limit' if entries_seen > 1024 else 'deadline'); break
                        if only_rc and not entry.name.startswith('rc'):
                            continue
                        path = directory / entry.name
                        if entry.is_symlink():
                            incomplete('symlink'); continue
                        if entry.is_dir(follow_symlinks=False):
                            queue.append((path, False)); continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        data = read_file(path)
                        if data is not None and path.suffix == '.plist':
                            found = candidates(data, allowed)
                            if found is None: incomplete('invalid_plist')
                            else:
                                pending.extend(found['paths'])
                                if found['arguments_truncated']: incomplete('argument_limit')
                        if result['files_considered'] >= 128:
                            incomplete('file_limit'); break
            finally:
                os.close(fd)
        except (OSError, ValueError):
            incomplete('unavailable')
        if entries_seen > 1024 or result['files_read'] >= 128:
            break
    for path in pending:
        if path in visited:
            continue
        if len(visited) >= 32:
            incomplete('candidate_limit'); break
        visited.add(path)
        result['candidate_count'] = len(visited)
        read_file(path)
    result['complete'] = not result['incomplete']
    return result


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
    try:
        for name, expected in (('kern.uuid', UUID), ('kern.hv_vmm_present', '1')):
            output = subprocess.run(['/usr/sbin/sysctl', '-n', name], check=True, capture_output=True, text=True, timeout=5)
            if output.stdout.strip() != expected: return False
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def main():
    if not guarded():
        print('{"event":"guard","status":"rejected"}', flush=True)
        return 1
    output = pathlib.Path(os.environ['RUNNER_TEMP']) / 'debug' / 'boot-policy-read.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    result = inventory(ROOTS, ALLOWED, time.monotonic() + 60, rc_root=pathlib.Path('/private/etc'))
    result['context'] = {'kernel_uuid': UUID, 'run_id': os.environ['GITHUB_RUN_ID'],
                         'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'head_sha': os.environ['GITHUB_SHA'],
                         'source_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
    output.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    print(json.dumps({'event': 'inventory_saved', 'complete': result['complete']}), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
