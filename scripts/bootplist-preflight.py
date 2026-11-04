#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

import recovery_bootargs as boot
import recovery_bootplist as core



class UpdateUncertain(Exception):
    def __init__(self, reason, returncode=None):
        super().__init__(reason)
        self.reason = reason
        self.returncode = returncode



def guarded():
    env = os.environ
    if (len(sys.argv) != 1 or os.geteuid() != 0 or sys.platform != 'darwin' or os.uname().machine != 'x86_64' or
        any(env.get(k) != v for k, v in {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'Code-Hex/vz-ci-test',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'RUNNER_ENVIRONMENT': 'github-hosted'}.items()) or
        not re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')) or
        not re.fullmatch(r'[1-9][0-9]{0,4}', env.get('GITHUB_RUN_ATTEMPT', '')) or
        not re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', ''))): return False
    try:
        for key, expected in (('kern.uuid', core.UUID), ('kern.hv_vmm_present', '1')):
            if boot.capture(['/usr/sbin/sysctl', '-n', key], 1024, 5).decode().strip() != expected: return False
        return boot.csr_allowed()
    except (OSError, ValueError, subprocess.SubprocessError): return False


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
                     'foreign_file', 'content_oversize', 'xattrs_oversize', 'xattrs_changed', 'xattrs_invalid', 'artifact_unavailable',
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
              'head_sha': os.environ['GITHUB_SHA'], 'kernel_uuid': core.UUID,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'bootargs_source_sha256': hashlib.sha256(Path(boot.__file__).read_bytes()).hexdigest(),
              'bootplist_source_sha256': hashlib.sha256(Path(core.__file__).read_bytes()).hexdigest()}
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
        info = core.read_plist(['/usr/sbin/diskutil', 'info', '-plist', '/'])
        groups = core.read_plist(['/usr/sbin/diskutil', 'apfs', 'listVolumeGroups', '-plist'])
        group, system = core.volume_ids(info, groups)
        paths = {core.PREBOOT / value / core.RELATIVE for value in (group, system)}
        pre_path, pre_original = core.select_preboot(paths)
        original = core.snapshot(core.DATA)
        data_flags, pre_flags = core.flags(original['raw']), core.flags(pre_original['raw'])
        if data_flags != pre_flags: raise ValueError('flags_mismatch')
        result['metadata'] = core.metadata_facts(core.DATA, original)
        if not core.metadata_allowed(result['metadata']): raise ValueError('metadata_unsupported')
        staged_raw = core.stage_content(original['raw'])
        for name, content in (('original.plist', original['raw']), ('original-metadata.json', json.dumps({k:v for k,v in original.items() if k != 'raw'}).encode())):
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(dfd)
        finally: os.close(dfd)
        result['data_original_sha256'] = hashlib.sha256(original['raw']).hexdigest()
        result['preboot_original_sha256'] = hashlib.sha256(pre_original['raw']).hexdigest()
        if not report('before_data_write'): raise ValueError('artifact_unavailable')
        staged = core.write_if_expected(core.DATA, original, staged_raw)
        changed = True
        result['data_staged_sha256'] = hashlib.sha256(staged_raw).hexdigest()
        if not core.same(core.snapshot(core.DATA), staged): raise ValueError('foreign_file')
        if not report('before_update'): raise ValueError('artifact_unavailable')
        result['first_update'] = update_preboot(report)
        report('after_update')
        if result['first_update'] not in ('returned_zero', 'returned_zero_late'): raise ValueError('update_failed')
        if not core.same(core.snapshot(core.DATA), staged): raise ValueError('foreign_file')
        selected_path, updated = core.select_preboot(paths)
        result['preboot_staged_match'] = selected_path == pre_path and core.flags(updated['raw'], allow_debug=True) == core.flags(staged_raw, allow_debug=True)
        result['status'] = 'observed'
    except UpdateUncertain as error:
        result['status'] = 'update_uncertain'
        result['update_error'] = update_error_fact(error)
        result['restoration'] = 'uncertain'
        changed = False
    except core.WriteUncertain:
        result['status'] = 'write_uncertain'
        result['restoration'] = 'uncertain'
        changed = False
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result['status'] = 'failed'
        result.update(error_fact(error))
    finally:
        if changed:
            try:
                report('before_restore')
                restored = core.write_if_expected(core.DATA, staged, original['raw'])
                result['restoration'] = 'data_written'
                if not core.same(core.snapshot(core.DATA), restored): raise ValueError('foreign_file')
                report('before_restore_update')
                result['restore_update'] = update_preboot(report)
                checked = core.snapshot(core.DATA)
                result['data_original_bytes_match'] = checked['raw'] == original['raw'] and core.same(checked, restored)
                selected_path, updated = core.select_preboot(paths)
                result['preboot_original_flags_match'] = selected_path == pre_path and core.flags(updated['raw']) == pre_flags
                result['data_metadata_match'] = core.metadata_preserved(original, checked)
                result['data_timestamps_match'] = core.restore_times(core.DATA, checked, original['atime_ns'], original['mtime_ns'])
                result['restoration'] = 'verified' if (result['restore_update'] in ('returned_zero', 'returned_zero_late') and result['data_original_bytes_match'] and result['preboot_original_flags_match'] and result['data_metadata_match'] and result['data_timestamps_match']) else 'failed'
            except UpdateUncertain as error:
                result['restoration'] = 'uncertain'
                result['restore_update_error'] = update_error_fact(error)
            except core.WriteUncertain:
                result['restoration'] = 'uncertain'
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                result['restoration'] = 'failed_or_foreign'
                result['restoration_error'] = error_fact(error)
        report('finished')
        for sig, handler in previous.items(): signal.signal(sig, handler)
    print(json.dumps({'event': 'preflight_finished', 'status': result['status'], 'restoration': result['restoration']}), flush=True)
    return 0 if not result.get('artifact_write_failed', False) and result['status'] == 'observed' and result.get('preboot_staged_match') is True and result['restoration'] == 'verified' else 1


if __name__ == '__main__': sys.exit(main())
