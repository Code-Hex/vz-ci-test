#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

import recovery_bootargs as boot

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
ENV_KEYS = ('GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_REF', 'GITHUB_EVENT_NAME',
            'RUNNER_ENVIRONMENT', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA')


def parse_native(data, code):
    try:
        if len(data) > 4096: raise ValueError()
        rows = [json.loads(line) for line in data.splitlines()]
        events = [row for row in rows if isinstance(row, dict) and row.get('event') == 'sync']
        if len(events) != 1: raise ValueError()
        event = events[0]
        if event.get('status') == 'returned':
            value = event.get('ioreturn')
            if type(value) is not int or not 0 <= value <= 0xffffffff: raise ValueError()
            if (code == 0) != (value == 0) or code not in (0, 70): raise ValueError()
            return {'status': 'returned', 'exit': code, 'ioreturn': value}
        if event.get('status') in ('options_unavailable', 'options_type_mismatch') and code == 69:
            return {'status': event['status'], 'exit': code}
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return {'status': 'invalid', 'exit': code}


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def native(helper, env):
    try:
        child = subprocess.Popen([str(helper), 'force-sync'], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return {'status': 'unavailable'}
    selector = selectors.DefaultSelector()
    data = bytearray()
    deadline = time.monotonic() + 10
    state = 'complete'
    try:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not selector.select(max(left, 0)):
                state = 'timeout_uncertain'; break
            chunk = os.read(child.stdout.fileno(), min(4097 - len(data), 4096))
            if not chunk: break
            data.extend(chunk)
            if len(data) > 4096:
                state = 'output_limit_uncertain'; break
        if state != 'complete': child.kill()
        try: code = child.wait(timeout=max(0.01, deadline - time.monotonic()) if state == 'complete' else 2)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait(timeout=2); state = 'timeout_uncertain'; code = None
        return parse_native(bytes(data), code) if state == 'complete' else {'status': state}
    finally:
        selector.close()
        if child.poll() is None:
            child.kill(); child.wait(timeout=2)
        child.stdout.close()


def guard():
    env = os.environ
    if (len(sys.argv) != 1 or os.geteuid() != 0 or sys.platform != 'darwin' or os.uname().machine != 'x86_64' or
        any(env.get(key) != expected for key, expected in {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'Code-Hex/vz-ci-test',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'RUNNER_ENVIRONMENT': 'github-hosted'}.items()) or
        not re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')) or
        not re.fullmatch(r'[1-9][0-9]{0,4}', env.get('GITHUB_RUN_ATTEMPT', '')) or
        not re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', ''))): return False
    try:
        for name, expected in (('kern.uuid', UUID), ('kern.hv_vmm_present', '1')):
            if boot.capture(['/usr/sbin/sysctl', '-n', name], 1024, 5).decode().strip() != expected: return False
        return boot.csr_allowed()
    except (OSError, ValueError, subprocess.SubprocessError): return False


def digest_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > 16 * 1024 * 1024:
            raise ValueError('invalid_file')
        return hashlib.sha256(stream.read(16 * 1024 * 1024 + 1)).hexdigest()


def checkpoint(result, phase, save):
    result['phase'] = phase
    try:
        save()
        return True
    except (OSError, KeyboardInterrupt):
        result['artifact_write_failed'] = True
        return False


def main():
    if not guard():
        print('{"event":"guard","status":"rejected"}', flush=True)
        return 1
    env = {key: os.environ[key] for key in ENV_KEYS}
    base = pathlib.Path(os.environ['RUNNER_TEMP'])
    helper = base / 'nvram-backend'
    output = base / 'debug' / 'nvram-staged-sync.json'
    binding = '/'.join((env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT'], env['GITHUB_SHA']))
    marker = {'binding': binding, 'nonce': secrets.token_hex(32)}
    result = {'binding': binding, 'kernel_uuid': UUID, 'plan_mode': 'native_retry_after_stage_cli_sync',
              'setup': 'pending', 'stage': 'not_attempted', 'stage_after_cli_sync': {'status': 'not_attempted'},
              'restore': 'not_attempted', 'restore_after_cli_sync': {'status': 'not_attempted'},
              'sameboot_readback_original': None, 'firmware_restoration_verified': False}
    def save_result():
        tmp = output.with_suffix('.tmp')
        tmp.write_text(json.dumps(result, separators=(',', ':')) + '\n')
        os.chmod(tmp, 0o644)
        os.replace(tmp, output)

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        save_result()
        private = base / 'debug' / 'private'
        private.mkdir(parents=True, mode=0o700, exist_ok=True)
        if private.is_symlink() or not private.is_dir(): raise ValueError('private_directory_invalid')
        os.chmod(private, 0o700)
        directory = private / 'staged-sync'
        directory.mkdir(mode=0o700)
        baseline = boot.capture(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'], 1024, 5).decode().strip().upper()
        if not re.fullmatch(r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}', baseline):
            raise ValueError('baseline_invalid')
        result.update({'baseline_boot_uuid': baseline, 'source_sha256': digest_regular(pathlib.Path(__file__)),
                       'bootargs_source_sha256': digest_regular(pathlib.Path(boot.__file__)),
                       'native_source_sha256': digest_regular(pathlib.Path('probes/nvram_backend.c')),
                       'native_binary_sha256': digest_regular(helper), 'setup': 'ready'})
        save_result()
    except (OSError, ValueError):
        result['setup'] = 'failed'
        try: save_result()
        except OSError: pass
        print('{"event":"setup","status":"failed"}', flush=True)
        return 1

    def interrupt(_number, _frame):
        raise KeyboardInterrupt()

    platform = boot.MacPlatform()
    old_handlers = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGTERM, signal.SIGHUP)}
    attempted = False
    try:
        if not checkpoint(result, 'stage_start', save_result):
            raise ValueError('artifact_write_failed')
        attempted = True
        boot.stage(directory, marker, platform, private_write, sync_directory)
        result['stage'] = 'verified_sameboot'
        result['stage_cli_sync_attempted'] = True
        original = boot.parse_nvram((directory / 'debug-boot-original.plist').read_bytes())
        staged = boot.parse_nvram((directory / 'debug-boot-staged.plist').read_bytes())
        result['before_stage_native_key_states'] = boot.key_states(original, staged, platform.read())[1]
        if result['before_stage_native_key_states'] != {'boot_args': 'staged', 'canary': 'staged'}:
            raise ValueError('staged_state_changed')
        if not checkpoint(result, 'staged_before_native', save_result):
            raise ValueError('artifact_write_failed')
        result['stage_after_cli_sync'] = native(helper, env)
        if not checkpoint(result, 'staged_native_returned', save_result):
            raise ValueError('artifact_write_failed')
        result['after_stage_native_key_states'] = boot.key_states(original, staged, platform.read())[1]
        if not checkpoint(result, 'staged_after_readback', save_result):
            raise ValueError('artifact_write_failed')
    except (Exception, KeyboardInterrupt):
        if result['stage'] == 'not_attempted': result['stage'] = 'failed_or_interrupted'
        result['experiment'] = 'failed_or_interrupted'
    finally:
        if attempted:
            checkpoint(result, 'restore_start', save_result)
            try:
                boot.rollback(directory, marker, platform, private_write, sync_directory)
                result['restore'] = 'returned'
                checkpoint(result, 'restore_returned', save_result)
                if (directory / 'debug-boot-original.plist').exists():
                    original = boot.parse_nvram((directory / 'debug-boot-original.plist').read_bytes())
                    current_boot = boot.capture(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'], 1024, 5).decode().strip().upper()
                    result['sameboot_readback_original'] = current_boot == baseline and platform.read() == original
                    checkpoint(result, 'restored_before_native', save_result)
                    if result['sameboot_readback_original']:
                        result['restore_after_cli_sync'] = native(helper, env)
                        checkpoint(result, 'restore_native_returned', save_result)
                        current_boot = boot.capture(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'], 1024, 5).decode().strip().upper()
                        result['sameboot_readback_original'] = current_boot == baseline and platform.read() == original
                        checkpoint(result, 'restore_after_readback', save_result)
                else:
                    result['restore'] = 'unstaged'
            except (Exception, KeyboardInterrupt):
                result['restore'] = 'failed_or_uncertain'
                result['sameboot_readback_original'] = None
        checkpoint(result, 'finished', save_result)
        for sig, handler in old_handlers.items(): signal.signal(sig, handler)
    print(json.dumps({'event': 'staged_sync_complete', 'stage': result['stage'],
                      'restore': result['restore'], 'sameboot_readback_original': result['sameboot_readback_original']}), flush=True)
    successful = (
        result.get('experiment') != 'failed_or_interrupted'
        and not result.get('artifact_write_failed', False)
        and result.get('after_stage_native_key_states') == {'boot_args': 'staged', 'canary': 'staged'}
        and result['stage'] == 'verified_sameboot'
        and result['restore'] == 'returned'
        and result['sameboot_readback_original'] is True
        and result['stage_after_cli_sync'].get('status') == 'returned'
        and result['stage_after_cli_sync'].get('ioreturn') == 0
        and result['restore_after_cli_sync'].get('status') == 'returned'
        and result['restore_after_cli_sync'].get('ioreturn') == 0
    )
    return 0 if successful else 1


if __name__ == '__main__':
    sys.exit(main())
