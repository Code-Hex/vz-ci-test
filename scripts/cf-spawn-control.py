#!/usr/bin/env python3
"""Compare fresh root and launchd children with and without the fixed CFData getter."""
import hashlib
import importlib.util
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

import recovery_nvram_panic as getter

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
CASES = ('direct_off', 'direct_on', 'launchd_off', 'launchd_on')
HEX = re.compile(r'[0-9a-f]{64}\Z')
BOOT = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')
SCOPE = re.compile(r'vz-cf-spawn-[1-9][0-9]{0,19}-[1-9][0-9]{0,4}-[0-9a-f]{16}\Z')


def valid_case(case):
    return isinstance(case, str) and case in CASES


def public_command(fact):
    allowed = ('ok', 'failed', 'timeout', 'unavailable', 'limit', 'pending', 'invalid')
    status = fact.get('status') if isinstance(fact, dict) else None
    status = status if isinstance(status, str) and status in allowed else 'invalid'
    code = fact.get('exit') if isinstance(fact, dict) else None
    count = fact.get('bytes') if isinstance(fact, dict) else None
    code = code if type(code) is int and -255 <= code <= 255 else None
    count = count if type(count) is int and 0 <= count <= 65536 else None
    if status == 'ok' and (code != 0 or count is None): status = 'invalid'
    return {'status': status, 'exit': code, 'bytes': count}


def selected_case(environment):
    case = environment.get('CF_SPAWN_CASE')
    if not valid_case(case): raise ValueError('case_invalid')
    return case


def sigchld_facts():
    disposition = 'unknown'; blocked = None
    try:
        value = signal.getsignal(signal.SIGCHLD)
        if value == signal.SIG_DFL: disposition = 'default'
        elif value == signal.SIG_IGN: disposition = 'ignored'
        elif callable(value): disposition = 'callable'
    except (OSError, ValueError): pass
    try: blocked = signal.SIGCHLD in signal.pthread_sigmask(signal.SIG_BLOCK, [])
    except (OSError, ValueError, AttributeError): pass
    return {'disposition': disposition, 'blocked': blocked}


def public_result(value, case):
    if not isinstance(value, dict) or value.get('case') != case or not valid_case(case): raise ValueError('result')
    raw_getter = value.get('getter')
    if not isinstance(raw_getter, dict): raise ValueError('result')
    status = raw_getter.get('status')
    if status not in ('skipped', 'pending', 'observed', 'empty', 'unavailable', 'unexpected_type', 'oversized'): status = 'invalid'
    size = raw_getter.get('bytes')
    digest_value = raw_getter.get('sha256')
    size = size if type(size) is int and 0 <= size <= getter.MAX_RAW else None
    digest_value = digest_value if isinstance(digest_value, str) and HEX.fullmatch(digest_value) else None
    if status == 'observed' and (size is None or digest_value is None): status = 'invalid'
    getter_fact = {'status': status, 'bytes': size, 'sha256': digest_value}
    raw_commands = value.get('commands')
    if not isinstance(raw_commands, dict): raise ValueError('result')
    commands = {name: public_command(raw_commands.get(name)) for name in ('echo', 'clang', 'dtrace_version')}
    raw_probe = value.get('probe')
    if not isinstance(raw_probe, dict): raise ValueError('result')
    enum_fields = {'list_status': ('unavailable', 'matched', 'ambiguous', 'missing'),
                   'list_stderr': ('unavailable', 'empty', 'permission', 'attach_failed', 'no_probes', 'compile_failed', 'other'),
                   'trace_stderr': ('unavailable', 'empty', 'permission', 'attach_failed', 'no_probes', 'compile_failed', 'other')}
    probe = {}
    for key, allowed in enum_fields.items():
        item = raw_probe.get(key)
        probe[key] = item if isinstance(item, str) and item in allowed else 'unavailable'
    for key in ('ready_count', 'hit_count'):
        item = raw_probe.get(key)
        probe[key] = item if type(item) is int and 0 <= item <= 65536 else None
    for key in ('list_exit', 'tracer_exit', 'helper_exit'):
        item = raw_probe.get(key)
        probe[key] = item if type(item) is int and -255 <= item <= 255 else None
    for key in ('provider_exact', 'function_exact', 'name_exact', 'released'):
        item = raw_probe.get(key)
        probe[key] = item if type(item) is bool else None
    probe_status = value.get('probe_status')
    if probe_status not in ('ok', 'failed', 'timeout', 'pending'): probe_status = 'invalid'
    if probe_status == 'ok' and not (probe['list_status'] == 'matched' and probe['list_exit'] == 0 and
            probe['ready_count'] == 1 and probe['hit_count'] == 1 and probe['released'] is True and
            all(probe[k] is True for k in ('provider_exact', 'function_exact', 'name_exact')) and
            probe['tracer_exit'] == 0 and probe['helper_exit'] == 0): probe_status = 'invalid'
    signals = {}
    for key in ('sigchld', 'sigchld_after'):
        raw_signal = value.get(key)
        if not isinstance(raw_signal, dict): raw_signal = {}
        disposition = raw_signal.get('disposition')
        if disposition not in ('default', 'ignored', 'callable', 'unknown'): disposition = 'unknown'
        blocked = raw_signal.get('blocked')
        signals[key] = {'disposition': disposition, 'blocked': blocked if type(blocked) is bool else None}
    stage = value.get('stage')
    if stage not in ('getter', 'echo', 'clang', 'dtrace_version', 'probe', 'done'): stage = 'unknown'
    cwd_root = value.get('cwd_is_root')
    cwd_root = cwd_root if type(cwd_root) is bool else None
    pid = value.get('child_pid')
    if type(pid) is not int or not 0 < pid < 2**31: raise ValueError('result')
    return {'case': case, 'child_pid': pid, 'stage': stage, 'cwd_is_root': cwd_root,
            **signals, 'getter': getter_fact, 'commands': commands, 'probe_status': probe_status, 'probe': probe}


def direct_argv(argv):
    return ['/bin/sh', '-c', 'cd / && exec "$@"', 'cf-spawn-child', *argv]


def preflight():
    path = Path(__file__).resolve().with_name('panic-source-preflight.py')
    spec = importlib.util.spec_from_file_location('cf_spawn_preflight', path)
    if not spec or not spec.loader: raise ValueError('source_invalid')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run_command(argv, directory, label, *, timeout=12):
    try:
        code, data = preflight().command(argv, directory, label, timeout=timeout, env=ENV)
        return {'status': 'ok' if code == 0 else 'failed', 'exit': code, 'bytes': len(data)}
    except (TimeoutError, subprocess.TimeoutExpired): return {'status': 'timeout', 'exit': None, 'bytes': None}
    except ValueError: return {'status': 'limit', 'exit': None, 'bytes': None}
    except (OSError, subprocess.SubprocessError): return {'status': 'unavailable', 'exit': None, 'bytes': None}


def sha(data): return hashlib.sha256(data).hexdigest()


def private_write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def private_read(path, mode, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != mode or info.st_size > limit): raise ValueError('file_invalid')
        data = stream.read(limit + 1)
        if len(data) != info.st_size: raise ValueError('file_invalid')
        return data


def python_identity(path):
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=True): raise ValueError('python')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or not mode & 0o111 or mode & 0o022 or
                not os.access(path, os.X_OK) or before.st_size > 64 * 1024 * 1024): raise ValueError('python')
        digest = hashlib.sha256()
        total = 0
        while True:
            data = stream.read(65536)
            if not data: break
            total += len(data)
            if total > 64 * 1024 * 1024: raise ValueError('python')
            digest.update(data)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if total != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields): raise ValueError('python')
        return {'uid': before.st_uid, 'dev': before.st_dev, 'ino': before.st_ino,
                'mode': mode, 'size': before.st_size, 'sha256': digest.hexdigest()}


def sysctl(name):
    value = subprocess.run(['/usr/sbin/sysctl', '-n', name], env=ENV, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=5, check=True).stdout
    if len(value) > 1024: raise ValueError('sysctl_invalid')
    return value.decode('ascii').strip()


def guard():
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'Code-Hex/vz-ci-test',
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'RUNNER_ENVIRONMENT': 'github-hosted'}
    if (os.geteuid() != 0 or sys.platform != 'darwin' or os.uname().machine != 'x86_64' or
            any(os.environ.get(k) != v for k, v in expected.items()) or
            not re.fullmatch(r'[1-9][0-9]{0,19}', os.environ.get('GITHUB_RUN_ID', '')) or
            not re.fullmatch(r'[1-9][0-9]{0,4}', os.environ.get('GITHUB_RUN_ATTEMPT', '')) or
            not re.fullmatch(r'[0-9a-f]{40}', os.environ.get('GITHUB_SHA', ''))): raise ValueError('guard')
    if sysctl('kern.uuid').upper() != UUID or sysctl('kern.hv_vmm_present') != '1': raise ValueError('guard')
    boot = sysctl('kern.bootsessionuuid')
    if not BOOT.fullmatch(boot): raise ValueError('guard')
    return boot.upper()


def helper_build(directory, nonce):
    p = preflight()
    source = p.helper_source(nonce).encode()
    private_write(directory / 'helper.c', source)
    helper = directory / 'helper'
    for argv, label in ((['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-O0', '-Wall', '-Wextra', '-Werror', str(directory / 'helper.c'), '-o', str(helper)], 'build'),
                        (['/usr/bin/codesign', '-s', '-', '-f', str(helper)], 'sign'),
                        (['/usr/bin/codesign', '--verify', '--strict', str(helper)], 'verify')):
        result = run_command(argv, directory, label)
        if result['status'] != 'ok': return {'status': result['status'], 'phase': label, 'exit': result['exit'], 'bytes': result['bytes']}, None
    helper.chmod(0o700)
    with helper.open('rb') as stream: os.fsync(stream.fileno())
    return {'status': 'ok', 'phase': 'verified', 'exit': 0, 'bytes': 0}, sha(private_read(helper, 0o700, 16 * 1024 * 1024))


def child_config(path):
    path = Path(path)
    if (not path.is_absolute() or path.name != 'config.json' or not valid_case(path.parent.name) or
            path.parent.parent.name != 'cases' or path.parent.parent.parent.parent != Path('/var/root').resolve(strict=True) or
            not SCOPE.fullmatch(path.parent.parent.parent.name) or path != path.resolve()): raise ValueError('scope')
    scope = path.parent.parent.parent
    for directory in (scope, scope / 'cases', path.parent):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('scope')
    config = json.loads(private_read(path, 0o600, 8192))
    if (not isinstance(config, dict) or set(config) != {'case', 'nonce', 'helper_sha', 'source_sha', 'preflight_sha', 'getter_sha', 'boot_uuid', 'run_id', 'attempt', 'head_sha', 'python_path', 'python_identity'} or
            config['case'] != path.parent.name or not all(isinstance(config[k], str) and HEX.fullmatch(config[k]) for k in ('nonce', 'helper_sha', 'source_sha', 'preflight_sha', 'getter_sha')) or
            not isinstance(config['boot_uuid'], str) or not BOOT.fullmatch(config['boot_uuid']) or
            not isinstance(config['run_id'], str) or not re.fullmatch(r'[1-9][0-9]{0,19}', config['run_id']) or
            not isinstance(config['attempt'], str) or not re.fullmatch(r'[1-9][0-9]{0,4}', config['attempt']) or
            not isinstance(config['head_sha'], str) or not re.fullmatch(r'[0-9a-f]{40}', config['head_sha']) or
            not scope.name.startswith('vz-cf-spawn-' + config['run_id'] + '-' + config['attempt'] + '-') or
            not isinstance(config['python_path'], str) or not Path(config['python_path']).is_absolute()): raise ValueError('config')
    python = Path(config['python_path'])
    if (python != Path(sys.executable).resolve(strict=True) or
            python_identity(python) != config['python_identity'] or
            Path(__file__).resolve() != scope / 'cf-spawn-control.py'): raise ValueError('binding')
    if (os.geteuid() != 0 or sys.platform != 'darwin' or os.uname().machine != 'x86_64' or
            sysctl('kern.uuid').upper() != UUID or sysctl('kern.hv_vmm_present') != '1' or
            sysctl('kern.bootsessionuuid').upper() != config['boot_uuid'].upper()): raise ValueError('guard')
    if sha(private_read(scope / 'cf-spawn-control.py', 0o600, 1024 * 1024)) != config['source_sha'] or sha(private_read(scope / 'panic-source-preflight.py', 0o600, 1024 * 1024)) != config['preflight_sha'] or sha(private_read(scope / 'recovery_nvram_panic.py', 0o600, 1024 * 1024)) != config['getter_sha'] or sha(private_read(path.parent / 'helper', 0o700, 16 * 1024 * 1024)) != config['helper_sha']:
        raise ValueError('binding')
    return config, path.parent


def save_progress(directory, result):
    temp = directory / 'progress.json.tmp'
    private_write(temp, json.dumps(result, separators=(',', ':')).encode())
    os.replace(temp, directory / 'progress.json')


def child(path):
    cwd_is_root = os.getcwd() == '/'
    config, directory = child_config(path)
    sigchld = sigchld_facts()
    facts = {'list_status': 'unavailable', 'list_exit': None, 'list_stderr': 'unavailable',
             'ready_count': 0, 'hit_count': 0, 'provider_exact': None, 'function_exact': None,
             'name_exact': None, 'released': False, 'tracer_exit': None, 'helper_exit': None,
             'trace_stderr': 'unavailable'}
    result = {'case': config['case'], 'child_pid': os.getpid(), 'sigchld': sigchld, 'sigchld_after': None, 'cwd_is_root': cwd_is_root, 'stage': 'getter',
              'getter': {'status': 'pending' if config['case'].endswith('_on') else 'skipped', 'bytes': None, 'sha256': None},
              'commands': {name: {'status': 'pending', 'exit': None, 'bytes': None}
                           for name in ('echo', 'clang', 'dtrace_version')},
              'probe_status': 'pending', 'probe': facts}
    save_progress(directory, result)
    if config['case'].endswith('_on'):
        status, raw = getter.read_panic_info()
        result['getter'] = {'status': status, 'bytes': len(raw) if raw is not None else None,
                            'sha256': sha(raw) if raw is not None else None}
        del raw
    result['sigchld_after'] = sigchld_facts()
    for name, argv in (('echo', ['/bin/echo', 'cf-control']),
                       ('clang', ['/usr/bin/xcrun', '--find', 'clang']),
                       ('dtrace_version', ['/usr/sbin/dtrace', '-V'])):
        result['stage'] = name; save_progress(directory, result)
        result['commands'][name] = public_command(run_command(argv, directory, name))
    result['stage'] = 'probe'; save_progress(directory, result)
    try:
        preflight().observe(directory / 'helper', config['nonce'], directory, facts, env=ENV)
        result['probe_status'] = 'ok'
    except (TimeoutError, subprocess.TimeoutExpired): result['probe_status'] = 'timeout'
    except (OSError, ValueError, subprocess.SubprocessError): result['probe_status'] = 'failed'
    result['stage'] = 'done'; save_progress(directory, result)
    private_write(directory / 'result.json.tmp', json.dumps(result, separators=(',', ':')).encode())
    os.replace(directory / 'result.json.tmp', directory / 'result.json')
    return 0


def controller():
    case = selected_case(os.environ)
    boot = guard()
    temp = Path(os.environ.get('RUNNER_TEMP', ''))
    if not temp.is_absolute(): raise ValueError('temp')
    run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    scope = Path('/var/root').resolve(strict=True) / ('vz-cf-spawn-' + run + '-' + attempt + '-' + secrets.token_hex(8))
    scope.mkdir(mode=0o700); cases_dir = scope / 'cases'; cases_dir.mkdir(mode=0o700)
    sources = {}
    for name in ('cf-spawn-control.py', 'panic-source-preflight.py', 'recovery_nvram_panic.py'):
        data = Path(__file__).resolve().with_name(name).read_bytes()
        private_write(scope / name, data); sources[name] = sha(data)
    python = Path(sys.executable).resolve(strict=True)
    python_info = python_identity(python)
    output = temp / 'debug' / 'cf-spawn-control.json'
    result = {'run_id': run, 'attempt': attempt, 'head_sha': os.environ['GITHUB_SHA'],
              'source_sha256': sources['cf-spawn-control.py'], 'kernel_uuid': UUID, 'boot_uuid': boot, 'cases': []}
    directory = cases_dir / case
    built = {'status': 'unavailable', 'phase': 'setup', 'exit': None, 'bytes': None}
    case_result = {'case': case, 'status': 'build_failed'}
    try:
        directory.mkdir(mode=0o700)
        nonce = secrets.token_hex(32)
        built, helper_sha = helper_build(directory, nonce)
        if built['status'] == 'ok':
            config = {'case': case, 'nonce': nonce, 'helper_sha': helper_sha, 'boot_uuid': boot,
                      'source_sha': sources['cf-spawn-control.py'], 'preflight_sha': sources['panic-source-preflight.py'],
                      'getter_sha': sources['recovery_nvram_panic.py'], 'run_id': run, 'attempt': attempt,
                      'head_sha': os.environ['GITHUB_SHA'], 'python_path': str(python), 'python_identity': python_info}
            private_write(directory / 'config.json', json.dumps(config, separators=(',', ':')).encode())
            bootout = None
            argv = [str(python), str(scope / 'cf-spawn-control.py'), 'child', str(directory / 'config.json')]
            if case.startswith('direct_'):
                result_child = run_command(direct_argv(argv), directory, 'child', timeout=90)
            else:
                label = 'com.codex.cfspawn.' + run + '.' + attempt + '.' + case + '.' + secrets.token_hex(8)
                plist_path = directory / 'job.plist'
                private_write(directory / 'daemon.stdout', b'')
                private_write(directory / 'daemon.stderr', b'')
                job = {'Label': label, 'ProgramArguments': ['/usr/bin/env', '-i', 'PATH=' + ENV['PATH'], 'LC_ALL=C', *argv],
                       'RunAtLoad': True, 'StandardOutPath': str(directory / 'daemon.stdout'),
                       'StandardErrorPath': str(directory / 'daemon.stderr')}
                private_write(plist_path, plistlib.dumps(job))
                try:
                    result_child = run_command(['/bin/launchctl', 'bootstrap', 'system', str(plist_path)], directory, 'bootstrap', timeout=10)
                    if result_child['status'] == 'ok':
                        deadline = time.monotonic() + 90
                        while time.monotonic() < deadline and not (directory / 'result.json').exists(): time.sleep(0.2)
                finally:
                    bootout = public_command(run_command(['/bin/launchctl', 'bootout', 'system/' + label], directory, 'bootout', timeout=10))
            try:
                value = json.loads(private_read(directory / 'result.json', 0o600, 65536))
                if public_command(result_child)['status'] != 'ok': raise ValueError('child_failed')
                case_result = {'case': case, 'status': 'observed', 'result': public_result(value, case)}
            except (OSError, ValueError, TypeError):
                case_result = {'case': case, 'status': 'child_unavailable', 'child': public_command(result_child)}
            if bootout is not None: case_result['bootout'] = bootout
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        case_result = {'case': case, 'status': 'case_error'}
    case_result['build'] = built
    case_result['context'] = 'direct_root' if case.startswith('direct_') else 'system_launchd'
    case_result['getter_requested'] = case.endswith('_on')
    if case_result['status'] in ('child_unavailable', 'case_error'):
        try:
            partial = json.loads(private_read(directory / 'progress.json', 0o600, 65536))
            case_result['partial'] = public_result(partial, case)
        except (OSError, ValueError, TypeError): pass
    result['cases'].append(case_result)
    payload = json.dumps(result, separators=(',', ':')).encode() + b'\n'
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = output.with_name(output.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(payload); stream.flush(); os.fchmod(stream.fileno(), 0o644); os.fsync(stream.fileno())
    os.replace(temporary, output)
    print(json.dumps({'status': 'complete', 'cases': 1}), flush=True)
    c = case_result
    passed = ((not case.startswith('launchd_') or c.get('bootout', {}).get('status') == 'ok') and
              c.get('result', {}).get('cwd_is_root') is True and c.get('result', {}).get('probe_status') == 'ok' and
              all(v['status'] == 'ok' for v in c['result']['commands'].values()) and
              (c['result']['getter']['status'] == 'observed' if case.endswith('_on') else c['result']['getter']['status'] == 'skipped'))
    return 0 if passed else 1


def main():
    try:
        if len(sys.argv) == 1: return controller()
        if len(sys.argv) == 3 and sys.argv[1] == 'child': return child(sys.argv[2])
    except (OSError, ValueError, TypeError, subprocess.SubprocessError): pass
    print(json.dumps({'status': 'failed'}), flush=True)
    return 1


if __name__ == '__main__': sys.exit(main())
