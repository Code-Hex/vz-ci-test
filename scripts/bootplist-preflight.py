#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import time

import recovery_bootargs as boot

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
DATA = Path('/Library/Preferences/SystemConfiguration/com.apple.Boot.plist')
PREBOOT = Path('/System/Volumes/Preboot')
RELATIVE = 'Library/Preferences/SystemConfiguration/com.apple.Boot.plist'
UUID_RE = re.compile(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\Z')


class UpdateUncertain(Exception):
    def __init__(self, reason, returncode=None):
        super().__init__(reason)
        self.reason = reason
        self.returncode = returncode


class ReplacementUncertain(Exception):
    pass


def volume_ids(info, groups):
    group = info.get('APFSVolumeGroupID') if isinstance(info, dict) else None
    if not isinstance(group, str) or not UUID_RE.fullmatch(group): raise ValueError('group_invalid')
    if not isinstance(groups, dict) or not isinstance(groups.get('Containers'), list): raise ValueError('groups_invalid')
    matches = []
    for container in groups['Containers']:
        if not isinstance(container, dict) or not isinstance(container.get('VolumeGroups'), list): continue
        matches.extend(item for item in container['VolumeGroups'] if isinstance(item, dict) and
                       isinstance(item.get('APFSVolumeGroupUUID'), str) and item['APFSVolumeGroupUUID'].upper() == group.upper())
    if len(matches) != 1 or not isinstance(matches[0].get('Volumes'), list): raise ValueError('group_ambiguous')
    systems = [item.get('DiskUUID') for item in matches[0]['Volumes'] if isinstance(item, dict) and item.get('Role') == 'System']
    if len(systems) != 1 or not isinstance(systems[0], str) or not UUID_RE.fullmatch(systems[0]): raise ValueError('system_ambiguous')
    return group.upper(), systems[0].upper()


def flags(raw, *, allow_debug=False):
    try: data = plistlib.loads(raw)
    except Exception as error: raise ValueError('plist_invalid') from error
    if not isinstance(data, dict) or not isinstance(data.get('Kernel Flags'), str): raise ValueError('flags_invalid')
    if not allow_debug:
        try: boot.check_unconfigured(data['Kernel Flags'])
        except ValueError as error: raise ValueError('existing_debug_configuration') from error
    return data['Kernel Flags']


def stage_content(raw):
    original = flags(raw)
    data = plistlib.loads(raw)
    data['Kernel Flags'] = original + (' ' if original else '') + 'debug=0x2000'
    return plistlib.dumps(data, fmt=plistlib.FMT_BINARY if raw.startswith(b'bplist00') else plistlib.FMT_XML, sort_keys=False)


def parent_fd(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('path_invalid')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
        return fd
    except BaseException:
        os.close(fd); raise


def snapshot(path):
    directory = parent_fd(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > 1024 * 1024: raise ValueError('file_invalid')
            raw = stream.read(st.st_size)
            after = os.fstat(stream.fileno())
            if (len(raw) != st.st_size or after.st_size != st.st_size or after.st_mtime_ns != st.st_mtime_ns or
                    after.st_ctime_ns != st.st_ctime_ns): raise ValueError('file_changed')
            return {'raw': raw, 'dev': st.st_dev, 'ino': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid,
                    'mode': stat.S_IMODE(st.st_mode), 'nlink': st.st_nlink, 'flags': getattr(st, 'st_flags', 0),
                    'atime_ns': st.st_atime_ns, 'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns}
    finally: os.close(directory)


def select_preboot(paths):
    found = []
    for path in set(paths):
        try: found.append((path, snapshot(path)))
        except FileNotFoundError: continue
    if len(found) != 1: raise ValueError('preboot_ambiguous')
    return found[0]


def same(a, b):
    return all(a[key] == b[key] for key in ('raw', 'dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'flags', 'mtime_ns', 'ctime_ns'))


def replace_if_expected(path, expected, content):
    if not same(snapshot(path), expected): raise ValueError('foreign_file')
    directory = parent_fd(path)
    name = '.vz-preflight-' + secrets.token_hex(16)
    rename_attempted = False
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content); stream.flush()
            os.fchown(stream.fileno(), expected['uid'], expected['gid'])
            os.fchmod(stream.fileno(), expected['mode'])
            os.utime(stream.fileno(), ns=(expected['atime_ns'], expected['mtime_ns']))
            os.fsync(stream.fileno())
        temp_path = path.parent / name
        temp_state = snapshot(temp_path)
        if any(temp_state[k] != expected[k] for k in ('uid', 'gid', 'mode', 'nlink', 'flags')) or not clean_metadata(temp_path, temp_state):
            raise ValueError('temporary_metadata_invalid')
        if not restore_times(temp_path, temp_state, expected['atime_ns'], expected['mtime_ns']):
            raise ValueError('temporary_times_invalid')
        if not same(snapshot(path), expected): raise ValueError('foreign_file')
        rename_attempted = True
        os.replace(name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        return snapshot(path)
    except BaseException as error:
        if rename_attempted: raise ReplacementUncertain() from error
        raise
    finally:
        try: os.unlink(name, dir_fd=directory)
        except OSError: pass
        os.close(directory)


def restore_times(path, expected, atime_ns, mtime_ns):
    if not same(snapshot(path), expected): raise ValueError('foreign_file')
    directory = parent_fd(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size) != (expected['dev'], expected['ino'], expected['mtime_ns'], expected['ctime_ns'], len(expected['raw'])):
                raise ValueError('foreign_file')
            os.utime(fd, ns=(atime_ns, mtime_ns))
            os.fsync(fd)
            st = os.fstat(fd)
            return st.st_atime_ns == atime_ns and st.st_mtime_ns == mtime_ns
        finally: os.close(fd)
    finally: os.close(directory)


def guarded():
    env = os.environ
    if (len(sys.argv) != 1 or os.geteuid() != 0 or sys.platform != 'darwin' or os.uname().machine != 'x86_64' or
        any(env.get(k) != v for k, v in {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'Code-Hex/vz-ci-test',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'RUNNER_ENVIRONMENT': 'github-hosted'}.items()) or
        not re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')) or
        not re.fullmatch(r'[1-9][0-9]{0,4}', env.get('GITHUB_RUN_ATTEMPT', '')) or
        not re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', ''))): return False
    try:
        for key, expected in (('kern.uuid', UUID), ('kern.hv_vmm_present', '1')):
            if boot.capture(['/usr/sbin/sysctl', '-n', key], 1024, 5).decode().strip() != expected: return False
        return boot.csr_allowed()
    except (OSError, ValueError, subprocess.SubprocessError): return False


def read_plist(args):
    return plistlib.loads(boot.capture(args, 4 * 1024 * 1024, 15))


def metadata_facts(path, original):
    result = {'uid_root': original['uid'] == 0, 'gid_root': original['gid'] == 0,
              'mode_0644': original['mode'] == 0o644, 'nlink_one': original['nlink'] == 1,
              'flags_zero': original['flags'] == 0, 'xattrs_empty': None, 'acl_empty': None,
              'identity_stable': False}
    try:
        attrs = boot.capture(['/usr/bin/xattr', str(path)], 4096, 5)
        result['xattrs_empty'] = not bool(attrs.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        acl = boot.capture(['/bin/ls', '-lde', str(path)], 8192, 5)
        result['acl_empty'] = len(acl.splitlines()) == 1
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        result['identity_stable'] = same(snapshot(path), original)
    except (OSError, ValueError):
        pass
    return result


def clean_metadata(path, original):
    facts = metadata_facts(path, original)
    return facts['xattrs_empty'] is True and facts['acl_empty'] is True and facts['identity_stable'] is True


def wait_for_update(child, record, timeout=30):
    late = False
    try:
        code = child.wait(timeout=timeout)
    except BaseException:
        late = True
        try: record('update_pending')
        except BaseException: pass
        while True:
            try:
                code = child.wait()
                break
            except BaseException:
                time.sleep(0.1)
    if code != 0:
        raise UpdateUncertain('nonzero', code)
    return 'returned_zero_late' if late else 'returned_zero'


def update_preboot(record):
    try:
        child = subprocess.Popen(['/usr/sbin/diskutil', 'apfs', 'updatePreboot', '/'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        raise
    except BaseException as error:
        raise UpdateUncertain('spawn_uncertain') from error
    return wait_for_update(child, record)


REASONS = frozenset(('group_invalid', 'groups_invalid', 'group_ambiguous', 'system_ambiguous',
                     'plist_invalid', 'flags_invalid', 'existing_debug_configuration', 'flags_mismatch',
                     'metadata_unsupported', 'path_invalid', 'file_invalid', 'file_changed', 'preboot_ambiguous',
                     'foreign_file', 'temporary_metadata_invalid', 'temporary_times_invalid', 'artifact_unavailable',
                     'update_failed'))


def update_error_fact(error):
    result = {'reason': error.reason if error.reason in ('nonzero', 'spawn_uncertain') else 'unknown'}
    if type(error.returncode) is int and -128 <= error.returncode <= 255:
        result['exit'] = error.returncode
    return result


def error_fact(error):
    if isinstance(error, OSError):
        code = error.errno
        return {'error_kind': 'os_error', 'errno': code if type(code) is int and 0 <= code <= 4095 else None}
    if isinstance(error, ValueError):
        reason = str(error)
        return {'error_kind': 'validation', 'reason': reason if reason in REASONS else 'invalid'}
    return {'error_kind': 'operation_failed'}


def main():
    if not guarded():
        print('{"event":"guard","status":"rejected"}', flush=True); return 1
    base = Path(os.environ['RUNNER_TEMP']) / 'debug'
    base.mkdir(parents=True, exist_ok=True)
    output = base / 'bootplist-preflight.json'
    result = {'phase': 'initial', 'status': 'incomplete', 'restoration': 'not_started',
              'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'],
              'head_sha': os.environ['GITHUB_SHA'], 'kernel_uuid': UUID,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    def report(phase):
        result['phase'] = phase
        temp = output.with_suffix('.tmp')
        try:
            temp.write_text(json.dumps(result, separators=(',', ':')) + '\n')
            os.replace(temp, output)
            return True
        except OSError:
            result['artifact_write_failed'] = True
            return False
    report('initial')
    private = base / 'private'
    private.mkdir(mode=0o700, exist_ok=True)
    if private.is_symlink() or not private.is_dir(): raise ValueError('private_invalid')
    os.chmod(private, 0o700)
    directory = private / 'bootplist-preflight'
    directory.mkdir(mode=0o700)
    changed = False
    staged = original = pre_original = pre_path = None
    previous = {sig: signal.signal(sig, lambda *_: None) for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    try:
        info = read_plist(['/usr/sbin/diskutil', 'info', '-plist', '/'])
        groups = read_plist(['/usr/sbin/diskutil', 'apfs', 'listVolumeGroups', '-plist'])
        group, system = volume_ids(info, groups)
        paths = {PREBOOT / value / RELATIVE for value in (group, system)}
        pre_path, pre_original = select_preboot(paths)
        original = snapshot(DATA)
        data_flags, pre_flags = flags(original['raw']), flags(pre_original['raw'])
        if data_flags != pre_flags: raise ValueError('flags_mismatch')
        result['metadata'] = metadata_facts(DATA, original)
        if not all(value is True for value in result['metadata'].values()): raise ValueError('metadata_unsupported')
        staged_raw = stage_content(original['raw'])
        for name, content in (('original.plist', original['raw']), ('original-metadata.json', json.dumps({k:v for k,v in original.items() if k != 'raw'}).encode())):
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(dfd)
        finally: os.close(dfd)
        result['data_original_sha256'] = hashlib.sha256(original['raw']).hexdigest()
        result['preboot_original_sha256'] = hashlib.sha256(pre_original['raw']).hexdigest()
        if not report('before_data_replace'): raise ValueError('artifact_unavailable')
        staged = replace_if_expected(DATA, original, staged_raw)
        changed = True
        result['data_staged_sha256'] = hashlib.sha256(staged_raw).hexdigest()
        if not report('before_update'): raise ValueError('artifact_unavailable')
        result['first_update'] = update_preboot(report)
        report('after_update')
        if result['first_update'] not in ('returned_zero', 'returned_zero_late'): raise ValueError('update_failed')
        selected_path, updated = select_preboot(paths)
        result['preboot_staged_match'] = selected_path == pre_path and flags(updated['raw'], allow_debug=True) == flags(staged_raw, allow_debug=True)
        result['status'] = 'observed'
    except UpdateUncertain as error:
        result['status'] = 'update_uncertain'
        result['update_error'] = update_error_fact(error)
        result['restoration'] = 'uncertain'
        changed = False
    except ReplacementUncertain:
        result['status'] = 'replacement_uncertain'
        result['restoration'] = 'uncertain'
        changed = False
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result['status'] = 'failed'
        result.update(error_fact(error))
    finally:
        if changed:
            try:
                report('before_restore')
                restored = replace_if_expected(DATA, staged, original['raw'])
                result['restoration'] = 'data_replaced'
                report('before_restore_update')
                result['restore_update'] = update_preboot(report)
                checked = snapshot(DATA)
                result['data_original_bytes_match'] = checked['raw'] == original['raw'] and same(checked, restored)
                selected_path, updated = select_preboot(paths)
                result['preboot_original_flags_match'] = selected_path == pre_path and flags(updated['raw']) == pre_flags
                result['data_metadata_match'] = all(checked[k] == original[k] for k in ('uid', 'gid', 'mode', 'nlink', 'flags', 'mtime_ns'))
                result['data_timestamps_match'] = restore_times(DATA, checked, original['atime_ns'], original['mtime_ns'])
                result['restoration'] = 'verified' if (result['restore_update'] in ('returned_zero', 'returned_zero_late') and result['data_original_bytes_match'] and result['preboot_original_flags_match'] and result['data_metadata_match'] and result['data_timestamps_match']) else 'failed'
            except UpdateUncertain as error:
                result['restoration'] = 'uncertain'
                result['restore_update_error'] = update_error_fact(error)
            except ReplacementUncertain:
                result['restoration'] = 'uncertain'
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                result['restoration'] = 'failed_or_foreign'
                result['restoration_error'] = error_fact(error)
        report('finished')
        for sig, handler in previous.items(): signal.signal(sig, handler)
    print(json.dumps({'event': 'preflight_finished', 'status': result['status'], 'restoration': result['restoration']}), flush=True)
    return 0 if not result.get('artifact_write_failed', False) and result['status'] == 'observed' and result.get('preboot_staged_match') is True and result['restoration'] == 'verified' else 1


if __name__ == '__main__': sys.exit(main())
