import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess

import recovery_bootargs as boot
from recovery_netdump_settings import DEBUG_MASK, NetdumpSettings, active_control

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
DATA = Path('/Library/Preferences/SystemConfiguration/com.apple.Boot.plist')
PREBOOT = Path('/System/Volumes/Preboot')
RELATIVE = 'Library/Preferences/SystemConfiguration/com.apple.Boot.plist'
UUID_RE = re.compile(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\Z')


class WriteUncertain(Exception):
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


def stage_content(raw, debug_mask=0x2000, *, nvram_paniclog=None, netdump_settings=None, boot_marker_nonce=None):
    if netdump_settings is not None and type(netdump_settings) is not NetdumpSettings:
        raise ValueError('netdump_settings_invalid')
    masks = (0x2000, 0x102000) if netdump_settings is None else (DEBUG_MASK,)
    if type(debug_mask) is not int or debug_mask not in masks: raise ValueError('debug_mask_invalid')
    if nvram_paniclog is not None and (type(nvram_paniclog) is not int or nvram_paniclog != 0 or debug_mask != 0x102000):
        raise ValueError('nvram_paniclog_invalid')
    if boot_marker_nonce is not None:
        boot._bootmarker_nonce(boot_marker_nonce)
        if debug_mask!=0x102000 or nvram_paniclog is not None or netdump_settings is not None: raise ValueError('boot_marker_mode_invalid')
    original = flags(raw)
    if boot_marker_nonce is not None and any(t.partition('=')[0].lstrip('-')=='vz_ci_nonce' for t in original.split()):
        raise ValueError('existing_boot_marker')
    if nvram_paniclog == 0 and any(token.partition('=')[0].lstrip('-') == 'nvram_paniclog' for token in original.split()):
        raise ValueError('existing_nvram_paniclog')
    data = plistlib.loads(raw)
    data['Kernel Flags'] = original + (' ' if original else '') + 'debug=0x' + format(debug_mask, 'x')
    if netdump_settings is not None:
        data['Kernel Flags'] += ' ' + ' '.join(netdump_settings.tokens())
    if nvram_paniclog == 0:
        data['Kernel Flags'] += ' nvram_paniclog=0'
    if boot_marker_nonce is not None:
        data['Kernel Flags'] += ' '+boot._bootmarker_nonce(boot_marker_nonce)
        if len(data['Kernel Flags'].encode('ascii'))>255 or any(ord(c)<32 or ord(c)>126 for c in data['Kernel Flags']):
            raise ValueError('boot_marker_arguments_invalid')
    boot.text(data['Kernel Flags'])
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


def xattr_fingerprint(fd):
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.flistxattr.restype = ctypes.c_ssize_t
    libc.fgetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.fgetxattr.restype = ctypes.c_ssize_t
    length = libc.flistxattr(fd, None, 0, 0x20)
    if length < 0: raise OSError(ctypes.get_errno(), 'flistxattr')
    if length > 8192: raise ValueError('xattrs_oversize')
    names = []
    if length:
        data = ctypes.create_string_buffer(length)
        if libc.flistxattr(fd, data, length, 0x20) != length: raise ValueError('xattrs_changed')
        raw = data.raw
        if not raw.endswith(b'\0'): raise ValueError('xattrs_invalid')
        names = raw[:-1].split(b'\0')
        if len(names) > 64 or len(set(names)) != len(names) or any(not name or len(name) > 127 for name in names):
            raise ValueError('xattrs_invalid')
    digest = hashlib.sha256()
    total = 0
    for name in sorted(names):
        size = libc.fgetxattr(fd, name, None, 0, 0, 0x20)
        if size < 0: raise OSError(ctypes.get_errno(), 'fgetxattr')
        total += size
        if size > 65536 or total > 131072: raise ValueError('xattrs_oversize')
        value = ctypes.create_string_buffer(size) if size else None
        if libc.fgetxattr(fd, name, value, size, 0, 0x20) != size: raise ValueError('xattrs_changed')
        digest.update(struct.pack('>HI', len(name), size)); digest.update(name)
        if size: digest.update(value.raw)
    return len(names), digest.hexdigest(), b'com.apple.decmpfs' in names


def snapshot_fd(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > 1024 * 1024: raise ValueError('file_invalid')
    raw = os.pread(fd, st.st_size, 0)
    count, fingerprint, compressed = xattr_fingerprint(fd)
    after = os.fstat(fd)
    if (len(raw) != st.st_size or after.st_size != st.st_size or after.st_mtime_ns != st.st_mtime_ns or
            after.st_ctime_ns != st.st_ctime_ns or after.st_dev != st.st_dev or after.st_ino != st.st_ino):
        raise ValueError('file_changed')
    return {'raw': raw, 'dev': st.st_dev, 'ino': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid,
            'mode': stat.S_IMODE(st.st_mode), 'nlink': st.st_nlink, 'flags': getattr(st, 'st_flags', 0),
            'atime_ns': st.st_atime_ns, 'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns,
            'xattr_count': count, 'xattr_sha256': fingerprint, 'compressed_xattr': compressed}


def snapshot(path):
    directory = parent_fd(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try: return snapshot_fd(fd)
        finally: os.close(fd)
    finally: os.close(directory)


def select_preboot(paths):
    found = []
    for path in set(paths):
        try: found.append((path, snapshot(path)))
        except FileNotFoundError: continue
    if len(found) != 1: raise ValueError('preboot_ambiguous')
    return found[0]


def same(a, b):
    return all(a[key] == b[key] for key in ('raw', 'dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'flags', 'mtime_ns', 'ctime_ns', 'xattr_count', 'xattr_sha256', 'compressed_xattr'))


def write_if_expected(path, expected, content, *, writer=os.pwrite):
    if not isinstance(content, bytes) or len(content) > 1024 * 1024: raise ValueError('content_oversize')
    directory = parent_fd(path)
    fd = None
    writing = False
    try:
        fd = os.open(path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        if not same(snapshot_fd(fd), expected) or not same(snapshot(path), expected): raise ValueError('foreign_file')
        if not acl_empty(path): raise ValueError('metadata_unsupported')
        if not same(snapshot_fd(fd), expected) or not same(snapshot(path), expected): raise ValueError('foreign_file')
        writing = True
        offset = 0
        while offset < len(content):
            count = writer(fd, content[offset:], offset)
            if not isinstance(count, int) or count <= 0: raise OSError('short_write')
            offset += count
        os.ftruncate(fd, len(content))
        os.fsync(fd)
        actual = snapshot_fd(fd)
        if (actual['raw'] != content or any(actual[k] != expected[k] for k in
                ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'flags', 'xattr_count', 'xattr_sha256', 'compressed_xattr'))):
            raise ValueError('write_mismatch')
        if not acl_empty(path) or not same(snapshot(path), actual) or not same(snapshot_fd(fd), actual):
            raise ValueError('write_mismatch')
        return actual
    except BaseException as error:
        if writing: raise WriteUncertain() from error
        raise
    finally:
        close_failed = False
        for opened in (fd, directory):
            if opened is not None:
                try: os.close(opened)
                except OSError: close_failed = True
        if close_failed:
            if writing: raise WriteUncertain()
            raise OSError('close_failed')


def metadata_preserved(original, current):
    return all(current[k] == original[k] for k in
               ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'flags', 'xattr_count', 'xattr_sha256', 'compressed_xattr'))


def restore_times(path, expected, atime_ns, mtime_ns):
    if not same(snapshot(path), expected): raise ValueError('foreign_file')
    directory = parent_fd(path)
    fd = None
    setting = False
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        if not same(snapshot_fd(fd), expected) or not acl_empty(path) or not same(snapshot(path), expected):
            raise ValueError('foreign_file')
        setting = True
        os.utime(fd, ns=(atime_ns, mtime_ns))
        os.fsync(fd)
        st = os.fstat(fd)
        count, digest, compressed = xattr_fingerprint(fd)
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if ((st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink,
             getattr(st, 'st_flags', 0), count, digest, compressed) !=
            (expected['dev'], expected['ino'], expected['uid'], expected['gid'], expected['mode'],
             expected['nlink'], expected['flags'], expected['xattr_count'], expected['xattr_sha256'], expected['compressed_xattr']) or
            (named.st_dev, named.st_ino) != (st.st_dev, st.st_ino) or
            st.st_atime_ns != atime_ns or st.st_mtime_ns != mtime_ns or not acl_empty(path)):
            raise ValueError('times_or_metadata_mismatch')
        after = os.fstat(fd)
        if after.st_ctime_ns != st.st_ctime_ns: raise ValueError('file_changed')
        return True
    except BaseException as error:
        if setting: raise WriteUncertain() from error
        raise
    finally:
        close_failed = False
        for opened in (fd, directory):
            if opened is not None:
                try: os.close(opened)
                except OSError: close_failed = True
        if close_failed:
            if setting: raise WriteUncertain()
            raise OSError('close_failed')

def read_plist(args):
    return plistlib.loads(boot.capture(args, 4 * 1024 * 1024, 15))


def acl_empty(path):
    try:
        acl = boot.capture(['/bin/ls', '-lde', str(path)], 8192, 5)
        return len(acl.splitlines()) == 1
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def metadata_facts(path, original):
    denied = stat.UF_IMMUTABLE | stat.UF_APPEND | stat.SF_IMMUTABLE | stat.SF_APPEND
    checks = {'uid_root': original['uid'] == 0, 'mode_0644': original['mode'] == 0o644,
              'nlink_one': original['nlink'] == 1, 'write_blocking_flags_absent': original['flags'] & denied == 0,
              'compression_absent': not (original['flags'] & stat.UF_COMPRESSED or original['compressed_xattr']),
              'xattrs_bounded': True, 'acl_empty': acl_empty(path), 'identity_stable': False}
    try: checks['identity_stable'] = same(snapshot(path), original)
    except (OSError, ValueError): pass
    return {'checks': checks, 'observed': {'gid': original['gid'], 'flags': original['flags'],
            'xattr_count': original['xattr_count'], 'xattr_sha256': original['xattr_sha256']}}


def metadata_allowed(facts):
    checks = facts.get('checks', {})
    return all(checks.get(key) is True for key in ('uid_root', 'mode_0644', 'nlink_one',
               'write_blocking_flags_absent', 'compression_absent', 'xattrs_bounded', 'acl_empty', 'identity_stable'))




def validate_marker(marker):
    if (not isinstance(marker, dict) or set(marker) != {'binding', 'nonce', 'baseline', 'source_identity'} or
            not isinstance(marker['binding'], str) or not re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}', marker['binding']) or
            not isinstance(marker['nonce'], str) or not re.fullmatch(r'[0-9a-f]{64}', marker['nonce']) or
            not isinstance(marker['source_identity'], str) or not re.fullmatch(r'[0-9a-f]{64}', marker['source_identity']) or
            not isinstance(marker['baseline'], str) or not UUID_RE.fullmatch(marker['baseline'])):
        raise ValueError('marker_invalid')


def resolve_paths():
    group, system = volume_ids(read_plist(['/usr/sbin/diskutil', 'info', '-plist', '/']),
                               read_plist(['/usr/sbin/diskutil', 'apfs', 'listVolumeGroups', '-plist']))
    path, _ = select_preboot({PREBOOT / value / RELATIVE for value in (group, system)})
    return DATA, path, group, system


def _meta(state):
    return {key: value for key, value in state.items() if key != 'raw'}


def _record(directory, name, value, save, sync):
    save(directory / name, json.dumps(value, separators=(',', ':')).encode())
    sync(directory)


def _load(directory, marker, data_path, preboot_path):
    validate_marker(marker)
    manifest = json.loads((directory / 'bootplist-manifest.json').read_text())
    keys={'marker','debug_mask','nvram_paniclog','netdump_settings','paths','scope','files'}
    if type(manifest) is not dict: raise ValueError('manifest_invalid')
    nonce=None
    if 'boot_marker_nonce' in manifest:
        keys.add('boot_marker_nonce'); nonce=manifest['boot_marker_nonce']
        boot._bootmarker_nonce(nonce)
        if nonce!=marker['nonce']: raise ValueError('manifest_invalid')
    if (set(manifest) != keys or
            manifest.get('marker') != marker or
            manifest.get('paths') != {'data': str(data_path), 'preboot': str(preboot_path)} or
            type(manifest.get('debug_mask')) is not int or
            (manifest['nvram_paniclog'] is not None and
             (type(manifest['nvram_paniclog']) is not int or manifest['nvram_paniclog'] != 0 or manifest['debug_mask'] != 0x102000)) or
            not isinstance(manifest['files'], dict) or set(manifest['files']) != {'data', 'preboot'}):
        raise ValueError('manifest_invalid')
    settings = None if manifest['netdump_settings'] is None else NetdumpSettings.from_record(manifest['netdump_settings'])
    saved = {}
    for name in ('data', 'preboot'):
        item = manifest.get('files', {}).get(name)
        if not isinstance(item, dict) or set(item) != {'meta', 'original_sha256', 'staged_sha256'}: raise ValueError('manifest_invalid')
        original = (directory / (name + '.original')).read_bytes()
        staged = (directory / (name + '.staged')).read_bytes()
        if hashlib.sha256(original).hexdigest() != item.get('original_sha256') or hashlib.sha256(staged).hexdigest() != item.get('staged_sha256'):
            raise ValueError('backup_invalid')
        if stage_content(original, manifest['debug_mask'], nvram_paniclog=manifest['nvram_paniclog'], netdump_settings=settings, boot_marker_nonce=nonce) != staged:
            raise ValueError('backup_invalid')
        saved[name] = {'original': original, 'staged': staged, 'meta': item['meta']}
    return saved, manifest['debug_mask'], settings, nonce


def _pending(directory, prefix, marker, saved, *, require_done=False):
    for name in ('data', 'preboot'):
        pending = directory / (name + '.' + prefix + '-pending.json')
        done = directory / (name + '.' + prefix + '-done.json')
        rejected = directory / (name + '.' + prefix + '-rejected.json')
        try:
            if not pending.exists():
                if done.exists() or rejected.exists() or require_done: raise WriteUncertain()
                continue
            if json.loads(pending.read_text()) != {'marker': marker}: raise WriteUncertain()
            if done.exists() == rejected.exists() or (require_done and not done.exists()): raise WriteUncertain()
            terminal = json.loads((done if done.exists() else rejected).read_text())
            if rejected.exists():
                if prefix != 'stage' or terminal != {'marker': marker}: raise WriteUncertain()
            elif prefix == 'stage':
                if set(terminal) != {'marker', 'meta'} or terminal['marker'] != marker: raise WriteUncertain()
                meta, original = terminal['meta'], saved[name]['meta']
                if not isinstance(meta, dict) or set(meta) != set(original): raise WriteUncertain()
                if any(type(meta[k]) is not type(original[k]) for k in original): raise WriteUncertain()
                if any(meta[k] != original[k] for k in ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'flags', 'xattr_count', 'xattr_sha256', 'compressed_xattr')): raise WriteUncertain()
            elif terminal != {'marker': marker, 'facts': {'bytes': True, 'metadata': True, 'timestamps': True}}:
                raise WriteUncertain()
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise WriteUncertain() from error


def _owned(saved, current):
    meta = saved['meta']
    return all(current[k] == meta[k] for k in ('ino', 'uid', 'gid', 'mode', 'nlink', 'flags',
                                                'xattr_count', 'xattr_sha256', 'compressed_xattr'))


def _state(saved, current):
    if not _owned(saved, current): return 'other'
    if current['raw'] == saved['original']: return 'original'
    if current['raw'] == saved['staged']: return 'staged'
    return 'other'


def _current_boot_uuid():
    return subprocess.check_output(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'], timeout=10).decode('ascii').strip()


def stage_files(directory, marker, data_path, preboot_path, save, sync, *, owner_uid=0, writer=write_if_expected, scope=None, boot_uuid=_current_boot_uuid, debug_mask=0x2000, nvram_paniclog=None, netdump_settings=None, boot_marker_nonce=None):
    validate_marker(marker)
    if boot_marker_nonce is not None and boot_marker_nonce!=marker['nonce']: raise ValueError('boot_marker_scope_invalid')
    directory = Path(directory); data_path = Path(data_path); preboot_path = Path(preboot_path)
    if (directory / 'bootplist-manifest.json').exists(): raise ValueError('already_staged')
    paths = {'data': data_path, 'preboot': preboot_path}
    originals = {name: snapshot(path) for name, path in paths.items()}
    if (originals['data']['dev'], originals['data']['ino']) == (originals['preboot']['dev'], originals['preboot']['ino']):
        raise ValueError('same_file')
    if flags(originals['data']['raw']) != flags(originals['preboot']['raw']): raise ValueError('flags_mismatch')
    for name, path in paths.items():
        check = metadata_facts(path, originals[name])
        check['checks']['uid_root'] = originals[name]['uid'] == owner_uid
        if not metadata_allowed(check): raise ValueError('metadata_unsupported')
    desired = {name: stage_content(item['raw'], debug_mask, nvram_paniclog=nvram_paniclog, netdump_settings=netdump_settings, boot_marker_nonce=boot_marker_nonce) for name, item in originals.items()}
    manifest = {'marker': marker, 'debug_mask': debug_mask, 'nvram_paniclog': nvram_paniclog,
                'netdump_settings': None if netdump_settings is None else netdump_settings.record(),
                'paths': {name: str(path) for name, path in paths.items()}, 'scope': scope, 'files': {}}
    if boot_marker_nonce is not None: manifest['boot_marker_nonce']=boot_marker_nonce
    for name in paths:
        original = originals[name]
        save(directory / (name + '.original'), original['raw'])
        save(directory / (name + '.staged'), desired[name])
        manifest['files'][name] = {'meta': _meta(original), 'original_sha256': hashlib.sha256(original['raw']).hexdigest(),
                                   'staged_sha256': hashlib.sha256(desired[name]).hexdigest()}
    _record(directory, 'bootplist-manifest.json', manifest, save, sync)
    for name, path in paths.items():
        try: _record(directory, name + '.stage-pending.json', {'marker': marker}, save, sync)
        except BaseException as error: raise WriteUncertain() from error
        try:
            current = writer(path, originals[name], desired[name])
        except WriteUncertain:
            raise
        except (OSError, ValueError):
            try: _record(directory, name + '.stage-rejected.json', {'marker': marker}, save, sync)
            except BaseException as error: raise WriteUncertain() from error
            rollback_files(directory, marker, data_path, preboot_path, save, sync, current_boot_uuid=boot_uuid())
            raise
        try:
            _record(directory, name + '.stage-done.json', {'marker': marker, 'meta': _meta(current)}, save, sync)
        except BaseException as error:
            raise WriteUncertain() from error
    try:
        for name, path in paths.items():
            done = json.loads((directory / (name + '.stage-done.json')).read_text())['meta']
            if not same(snapshot(path), {**done, 'raw': desired[name]}) or not acl_empty(path): raise WriteUncertain()
    except BaseException as error: raise WriteUncertain() from error
    try: _record(directory, 'bootplist-stage-complete.json', {'marker': marker}, save, sync)
    except BaseException as error: raise WriteUncertain() from error
    return {'data': 'staged', 'preboot': 'staged', 'metadata_preserved': True}


def _restore_files(directory, marker, paths, saved, states, save, sync):
    facts = {}
    try:
        for name in ('preboot', 'data'):
            current = snapshot(paths[name])
            if _state(saved[name], current) != states[name] or states[name] == 'other' or not acl_empty(paths[name]): raise WriteUncertain()
            _record(directory, name + '.restore-pending.json', {'marker': marker}, save, sync)
            if states[name] == 'staged': current = write_if_expected(paths[name], current, saved[name]['original'])
            if not restore_times(paths[name], current, saved[name]['meta']['atime_ns'], saved[name]['meta']['mtime_ns']): raise WriteUncertain()
            facts[name] = {'bytes': current['raw'] == saved[name]['original'],
                           'metadata': _owned(saved[name], current), 'timestamps': True}
            if not all(facts[name].values()): raise WriteUncertain()
            _record(directory, name + '.restore-done.json', {'marker': marker, 'facts': facts[name]}, save, sync)
    except BaseException as error:
        raise WriteUncertain() from error
    return facts


def rollback_files(directory, marker, data_path, preboot_path, save, sync, *, current_boot_uuid):
    validate_marker(marker)
    if (not isinstance(current_boot_uuid, str) or not UUID_RE.fullmatch(current_boot_uuid) or
            current_boot_uuid.upper() != marker['baseline'].upper()):
        raise ValueError('rollback_boot_mismatch')
    directory = Path(directory); data_path = Path(data_path); preboot_path = Path(preboot_path)
    saved, _, _, _ = _load(directory, marker, data_path, preboot_path)
    _pending(directory, 'stage', marker, saved); _pending(directory, 'restore', marker, saved)
    paths = {'data': data_path, 'preboot': preboot_path}
    current = {name: snapshot(path) for name, path in paths.items()}
    states = {name: _state(saved[name], item) if acl_empty(paths[name]) and same(snapshot(paths[name]), item) else 'other' for name, item in current.items()}
    if 'other' in states.values(): raise ValueError('foreign_file')
    for name in paths:
        done = directory / (name + '.stage-done.json')
        expected = json.loads(done.read_text())['meta'] if done.exists() else saved[name]['meta']
        expected = {**expected, 'raw': saved[name][states[name]]}
        if not same(current[name], expected): raise ValueError('foreign_file')
    _restore_files(directory, marker, paths, saved, states, save, sync)
    return {'restored': True}


def finish_files(directory, marker, data_path, preboot_path, current_boot_uuid, active_mask, save, sync, *, active_status='observed'):
    directory = Path(directory); data_path = Path(data_path); preboot_path = Path(preboot_path)
    if not isinstance(current_boot_uuid, str) or not UUID_RE.fullmatch(current_boot_uuid) or current_boot_uuid.upper() == marker['baseline'].upper():
        raise ValueError('boot_invalid')
    if (active_status not in ('observed', 'unavailable', 'invalid') or (active_status != 'observed' and active_mask is not None) or
            (active_mask is not None and (type(active_mask) is not int or not 0 <= active_mask <= 0xffffffff))): raise ValueError('active_invalid')
    saved, expected_mask, _, _ = _load(directory, marker, data_path, preboot_path)
    if active_status == 'observed':
        active_status = 'observed_debug' if active_mask == expected_mask else 'observed_no_debug'
    _pending(directory, 'stage', marker, saved, require_done=True); _pending(directory, 'restore', marker, saved)
    try:
        if json.loads((directory / 'bootplist-stage-complete.json').read_text()) != {'marker': marker}: raise WriteUncertain()
    except (OSError, ValueError) as error:
        raise WriteUncertain() from error
    receipt_path = directory / 'bootplist-restored.json'
    if receipt_path.exists():
        try:
            receipt = json.loads(receipt_path.read_text())
            observation = json.loads((directory / 'bootplist-observation.json').read_text())
            keys = {'marker', 'current_boot_uuid', 'bootplist_file_states', 'active_debug_mask',
                    'active_bootargs_status', 'bootplist_restored', 'bootplist_restore'}
            if set(receipt) != keys or receipt['marker'] != marker or receipt['current_boot_uuid'] != current_boot_uuid.upper(): raise WriteUncertain()
            if observation != {k: receipt[k] for k in ('marker', 'current_boot_uuid', 'bootplist_file_states', 'active_debug_mask', 'active_bootargs_status')}: raise WriteUncertain()
            states = receipt['bootplist_file_states']
            if not isinstance(states, dict) or set(states) != {'data', 'preboot'} or any(v not in ('original', 'staged', 'other') for v in states.values()): raise WriteUncertain()
            if type(receipt['bootplist_restored']) is not bool: raise WriteUncertain()
            expected = {name: {'bytes': True, 'metadata': True, 'timestamps': True} for name in ('data', 'preboot')}
            if receipt['bootplist_restore'] != (expected if receipt['bootplist_restored'] else {}): raise WriteUncertain()
            if receipt['bootplist_restored'] != ('other' not in states.values()): raise WriteUncertain()
            return {k: v for k, v in receipt.items() if k != 'marker'}
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise WriteUncertain() from error
    paths = {'data': data_path, 'preboot': preboot_path}
    current = {name: snapshot(path) for name, path in paths.items()}
    states = {name: _state(saved[name], item) if acl_empty(paths[name]) and same(snapshot(paths[name]), item) else 'other' for name, item in current.items()}
    observation = {'marker': marker, 'current_boot_uuid': current_boot_uuid.upper(), 'bootplist_file_states': states, 'active_debug_mask': active_mask,
                   'active_bootargs_status': active_status}
    if (directory / 'bootplist-observation.json').exists(): raise WriteUncertain()
    try: _record(directory, 'bootplist-observation.json', observation, save, sync)
    except BaseException as error: raise WriteUncertain() from error
    result = {'current_boot_uuid': current_boot_uuid.upper(), 'bootplist_file_states': states, 'active_debug_mask': active_mask,
              'active_bootargs_status': active_status, 'bootplist_restored': False, 'bootplist_restore': {}}
    if 'other' in states.values():
        try: _record(directory, 'bootplist-restored.json', {'marker': marker, **result}, save, sync)
        except BaseException as error: raise WriteUncertain() from error
        return result
    restored_facts = _restore_files(directory, marker, paths, saved, states, save, sync)
    result['bootplist_restore'] = restored_facts
    result['bootplist_restored'] = True
    try: _record(directory, 'bootplist-restored.json', {'marker': marker, **result}, save, sync)
    except BaseException as error: raise WriteUncertain() from error
    return result


def stage(directory, marker, save, sync, *, debug_mask=0x2000, nvram_paniclog=None, netdump_settings=None, boot_marker_nonce=None):
    data, preboot, group, system = resolve_paths()
    result = stage_files(directory, marker, data, preboot, save, sync, scope={'group': group, 'system': system},
                         debug_mask=debug_mask, nvram_paniclog=nvram_paniclog, netdump_settings=netdump_settings, boot_marker_nonce=boot_marker_nonce)
    return result


def _production_paths(directory, marker):
    validate_marker(marker)
    manifest = json.loads((Path(directory) / 'bootplist-manifest.json').read_text())
    paths = manifest.get('paths', {})
    preboot = Path(paths.get('preboot', ''))
    if paths.get('data') != str(DATA) or len(preboot.parts) != len(PREBOOT.parts) + 1 + len(Path(RELATIVE).parts):
        raise ValueError('manifest_invalid')
    relative = preboot.relative_to(PREBOOT)
    scope = manifest.get('scope')
    if (not isinstance(scope, dict) or set(scope) != {'group', 'system'} or
            any(not isinstance(scope[k], str) or not UUID_RE.fullmatch(scope[k]) for k in scope) or
            relative.parts[0].upper() not in (scope['group'].upper(), scope['system'].upper()) or
            Path(*relative.parts[1:]) != Path(RELATIVE)): raise ValueError('manifest_invalid')
    return DATA, preboot


def rollback(directory, marker, save, sync, *, current_boot_uuid):
    data, preboot = _production_paths(directory, marker)
    return rollback_files(directory, marker, data, preboot, save, sync, current_boot_uuid=current_boot_uuid)


def _control_profile(value, mask, maximum):
    if (type(value) is not dict or set(value) != {'status', 'debug_mask', 'nondebug_token_count', 'nondebug_sha256'} or
            value['status'] != 'observed' or type(value['debug_mask']) is not type(mask) or value['debug_mask'] != mask or
            type(value['nondebug_token_count']) is not int or not 0 <= value['nondebug_token_count'] <= maximum or
            type(value['nondebug_sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', value['nondebug_sha256'])):
        raise ValueError('active_control_invalid')
    return dict(value)


def _checked_capture(value, scope, settings, baseline):
    if type(value) is not dict or set(value) != {'scope', 'active_mask', 'active_status', 'control'} or value['scope'] != scope:
        raise ValueError('active_capture_invalid')
    mask, status, control = value['active_mask'], value['active_status'], value['control']
    if (status not in ('observed', 'invalid', 'unavailable') or
            (mask is not None and (type(mask) is not int or not 0 <= mask <= 0xffffffff)) or
            (status != 'observed' and mask is not None) or type(control) is not dict):
        raise ValueError('active_capture_invalid')
    if control.get('status') in ('invalid', 'unavailable'):
        if (set(control) != {'status'} or (status != 'observed' and control != {'status': status}) or
                (control['status'] == 'unavailable' and status != 'unavailable')):
            raise ValueError('active_capture_invalid')
    else:
        if (set(control) != {'status', 'settings_sha256', 'full_profile', 'remaining_profile'} or
                control['status'] != 'observed' or control['settings_sha256'] != settings.digest() or
                status != 'observed' or mask != DEBUG_MASK or baseline is None):
            raise ValueError('active_capture_invalid')
        full = _control_profile(control['full_profile'], DEBUG_MASK, 516)
        remaining = _control_profile(control['remaining_profile'], DEBUG_MASK, 512)
        if (full['nondebug_token_count'] != remaining['nondebug_token_count'] + 4 or
                any(remaining[key] != baseline[key] for key in ('nondebug_token_count', 'nondebug_sha256'))):
            raise ValueError('active_capture_invalid')
    return value


def _netdump_capture(directory, marker, current, settings, baseline, save, sync):
    invalid = {'active_mask': None, 'active_status': 'invalid', 'control': {'status': 'invalid'}}
    try:
        try: baseline = _control_profile(baseline, None, 512)
        except ValueError: baseline = None
        scope = {'marker': marker, 'current_boot_uuid': current.upper(), 'settings_sha256': settings.digest(),
                 'baseline_profile_sha256': hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        started, captured = directory / 'bootplist-active-started.json', directory / 'bootplist-active-capture.json'
        if any(path.exists() for path in (started, captured, directory / 'bootplist-observation.json', directory / 'bootplist-restored.json')):
            if json.loads(started.read_text()) != scope: return invalid
            raw = captured.read_bytes()
            if len(raw) > 8192: return invalid
            return _checked_capture(json.loads(raw), scope, settings, baseline)
        _record(directory, started.name, scope, save, sync)
        mask, status, control = None, 'unavailable', {'status': 'unavailable'}
        try:
            raw = boot.MacPlatform().active()
            mask = boot.debug_mask(settings.strip_owned(raw))
            status = 'observed'
            try: control = active_control(raw, settings, baseline)
            except ValueError: control = {'status': 'invalid'}
        except ValueError:
            status, control = 'invalid', {'status': 'invalid'}
        except (OSError, subprocess.SubprocessError):
            pass
        value = _checked_capture({'scope': scope, 'active_mask': mask, 'active_status': status, 'control': control}, scope, settings, baseline)
        _record(directory, captured.name, value, save, sync)
        return value
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        return invalid


def _marker_json(path):
    with path.open('rb') as stream: raw=stream.read(8193)
    if len(raw)>8192: raise ValueError('boot_marker_cache_invalid')
    return json.loads(raw)


def _checked_marker_capture(value, scope, nonce, baseline):
    if type(value) is not dict or set(value)!={'scope','active_mask','active_status','control'} or value['scope']!=scope:
        raise ValueError('boot_marker_cache_invalid')
    mask,status=value['active_mask'],value['active_status']
    if (status not in ('observed','invalid','unavailable') or
            (mask is not None and (type(mask) is not int or not 0<=mask<=0xffffffff)) or
            (status!='observed' and mask is not None)):
        raise ValueError('boot_marker_cache_invalid')
    control=boot.checked_bootmarker_control(value['control'],nonce,baseline)
    if ((control['status']=='observed' and (status!='observed' or mask!=0x102000)) or
            (control['status'] in ('unavailable','uncertain') and status!='unavailable')):
        raise ValueError('boot_marker_cache_invalid')
    return value


def _bootmarker_capture(directory, marker, current, nonce, baseline, save, sync):
    def negative(status):
        return {'active_mask':None,'active_status':'invalid' if status=='invalid' else 'unavailable','control':{'status':status}}
    try:
        scope={'marker':marker,'current_boot_uuid':current.upper(),'mode':'bootargs-marker'}
        started=directory/'boot-marker-started.json'; captured=directory/'boot-marker-observation.json'
        if started.exists() or captured.exists():
            try:
                if _marker_json(started)!=scope: return negative('invalid')
                if not captured.exists(): return negative('uncertain')
                return _checked_marker_capture(_marker_json(captured),scope,nonce,baseline)
            except (ValueError,TypeError,KeyError): return negative('invalid')
        if any((directory/name).exists() for name in ('debug-boot-core.json','bootplist-observation.json','bootplist-restored.json','data.restore-pending.json','preboot.restore-pending.json','data.restore-done.json','preboot.restore-done.json')):
            return negative('uncertain')
        _record(directory,started.name,scope,save,sync)
        mask,status,control=None,'unavailable',{'status':'unavailable'}
        try:
            raw=boot.capture(['/usr/sbin/sysctl','-n','kern.bootargs'],1025,timeout=8)
            mask=boot.debug_mask(boot.decode_bootmarker_stdout(raw)); status='observed'
            try: control=boot.bootmarker_control(raw,nonce,baseline)
            except ValueError: control={'status':'invalid'}
        except ValueError:
            mask,status,control=None,'invalid',{'status':'invalid'}
        except (OSError,subprocess.SubprocessError): pass
        value=_checked_marker_capture({'scope':scope,'active_mask':mask,'active_status':status,'control':control},scope,nonce,baseline)
        _record(directory,captured.name,value,save,sync)
        return value
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):
        return negative('uncertain')


def finish(directory, marker, save, sync, *, current_boot_uuid, baseline_boot_argument_profile=None):
    data, preboot = _production_paths(directory, marker)
    _, _, settings, nonce = _load(directory, marker, data, preboot)
    if nonce is not None:
        if (type(current_boot_uuid) is not str or not UUID_RE.fullmatch(current_boot_uuid) or
                current_boot_uuid.upper()==marker['baseline'].upper()): raise ValueError('boot_invalid')
        capture=_bootmarker_capture(Path(directory),marker,current_boot_uuid,nonce,baseline_boot_argument_profile,save,sync)
        result=finish_files(directory,marker,data,preboot,current_boot_uuid,capture['active_mask'],save,sync,active_status=capture['active_status'])
        status=capture['active_status']
        if status=='observed': status='observed_debug' if capture['active_mask']==0x102000 else 'observed_no_debug'
        same_capture=result['active_debug_mask']==capture['active_mask'] and result['active_bootargs_status']==status
        mismatch='uncertain' if result['active_bootargs_status']=='unavailable' else 'invalid'
        result['boot_marker_control']=(capture['control'] if capture['control']['status']!='observed' or same_capture else {'status':mismatch})
        return result
    if settings is not None:
        if (not isinstance(current_boot_uuid, str) or not UUID_RE.fullmatch(current_boot_uuid) or
                current_boot_uuid.upper() == marker['baseline'].upper()): raise ValueError('boot_invalid')
        capture = _netdump_capture(Path(directory), marker, current_boot_uuid, settings, baseline_boot_argument_profile, save, sync)
        result = finish_files(directory, marker, data, preboot, current_boot_uuid, capture['active_mask'], save, sync,
                              active_status=capture['active_status'])
        status = capture['active_status']
        if status == 'observed': status = 'observed_debug' if capture['active_mask'] == DEBUG_MASK else 'observed_no_debug'
        result['netdump_active_control'] = (capture['control'] if result['active_debug_mask'] == capture['active_mask'] and
                                            result['active_bootargs_status'] == status else {'status': 'invalid'})
        return result
    try:
        active = boot.MacPlatform().active()
        active_mask = boot.debug_mask(active)
        active_status = 'observed'
    except ValueError:
        active_mask = None
        active_status = 'unavailable'
    except (OSError, subprocess.SubprocessError):
        active_mask = None
        active_status = 'unavailable'
    return finish_files(directory, marker, data, preboot, current_boot_uuid, active_mask, save, sync, active_status=active_status)
