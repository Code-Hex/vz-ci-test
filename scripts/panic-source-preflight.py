#!/usr/bin/env python3
"""Non-destructive PID probe and panic-action compile-only control."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import stat
import sys
import time

import recovery_nvram_panic
import nonce_usdt as usdt

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
LIMIT = 65536


def validate_control_kind(control_kind):
    if type(control_kind) is not str or control_kind not in ('pid-v1', 'usdt-v1'): raise ValueError('control_kind_invalid')


def helper_source(nonce, *, control_kind='pid-v1'):
    validate_control_kind(control_kind)
    if control_kind == 'usdt-v1':
        spec = usdt.ProbeSpec(nonce)
        return ('#include "provider.h"\n#include <unistd.h>\n#include <stdio.h>\n#include <errno.h>\n' +
                usdt.function_source(spec).decode('ascii') +
                'int main(void) { char c; ssize_t n; setvbuf(stdout, NULL, _IONBF, 0); '
                'printf("HELPER_READY %ld\\n", (long)getpid()); '
                'do { n = read(STDIN_FILENO, &c, 1); } while (n < 0 && errno == EINTR); '
                "if (n != 1 || c != 'G') return 1; " + spec.function + '(); return 0; }\n')
    if not re.fullmatch(r'[0-9a-f]{64}', nonce): raise ValueError('invalid_nonce')
    return ('#include <unistd.h>\n'
            '__attribute__((noinline,used,visibility("default"))) void vz_nonce_' + nonce + '(void) { __asm__ volatile(""); }\n'
            'int main(void) { char c; if (read(STDIN_FILENO, &c, 1) != 1 || c != \'G\') return 1; '
            'vz_nonce_' + nonce + '(); return 0; }\n')


def probe_script(nonce, destructive):
    if not re.fullmatch(r'[0-9a-f]{64}', nonce): raise ValueError('invalid_nonce')
    probe = 'pid$target::vz_nonce_' + nonce + ':entry'
    if destructive: return probe + ' { panic(); }'
    return ('dtrace:::BEGIN { printf("READY\\n"); } ' + probe +
            ' { printf("HIT %s:%s:%s:%s\\n", probeprov, probemod, probefunc, probename); exit(0); }')


def parse_probe_list(text, pid, name):
    matches = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 5 and fields[0].isdigit() and fields[1] == 'pid' + str(pid) and fields[3:] == [name, 'entry']:
            matches.append(fields[2])
    return 'matched' if len(matches) == 1 else 'ambiguous' if matches else 'missing'


def events_valid(data, pid, name):
    lines = [line.strip() for line in data.splitlines() if line.strip()]
    if len(lines) != 2 or lines[0] != b'READY': return False
    pattern = rb'HIT pid' + str(pid).encode() + rb':[A-Za-z0-9_.+-]+:' + re.escape(name.encode()) + rb':entry'
    return bool(re.fullmatch(pattern, lines[1]))


def event_facts(data, pid, name):
    lines = [line.strip() for line in data.splitlines()]
    hits = [line[4:].split(b':') for line in lines if line.startswith(b'HIT ')]
    fields = hits[0] if len(hits) == 1 and len(hits[0]) == 4 else None
    return {'ready_count': lines.count(b'READY'), 'hit_count': len(hits),
            'nonempty_line_count': sum(bool(line) for line in lines),
            'provider_exact': fields[0] == ('pid' + str(pid)).encode() if fields else None,
            'function_exact': fields[2] == name.encode() if fields else None,
            'name_exact': fields[3] == b'entry' if fields else None}


def stderr_kind(data):
    lower = data.lower()
    if not lower: return 'empty'
    if b'permission denied' in lower or b'not permitted' in lower: return 'permission'
    if b'failed to grab' in lower or b'failed to attach' in lower: return 'attach_failed'
    if b'no probes' in lower or b'no probe matches' in lower: return 'no_probes'
    if b'failed to compile' in lower or b'syntax error' in lower: return 'compile_failed'
    return 'other'


def write_public(path, result):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, separators=(',', ':'))
        stream.write('\n'); stream.flush(); os.fchmod(stream.fileno(), 0o644); os.fsync(stream.fileno())


def open_private(path, *, append=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_APPEND if append else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise OSError('private_file_invalid')
        return os.fdopen(fd, 'ab' if append else 'wb')
    except BaseException:
        os.close(fd)
        raise


def notify_timeout(on_timeout, child):
    if on_timeout is not None:
        try: on_timeout(child)
        except BaseException: pass


def command(argv, directory, label, timeout=15, *, env=None, on_timeout=None):
    with open_private(directory / (label + '.stdout')) as sink, open_private(directory / (label + '.stderr')) as errors:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, sink)
        selector.register(child.stderr, selectors.EVENT_READ, errors)
        data = bytearray(); total = 0; deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise TimeoutError()
                events = selector.select(remaining)
                if not events: raise TimeoutError()
                for key, _ in events:
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj); continue
                    total += len(chunk)
                    if total > LIMIT: raise ValueError('output_limit')
                    key.data.write(chunk)
                    if key.fileobj is child.stdout: data.extend(chunk)
            result = child.wait(timeout=max(0.1, deadline - time.monotonic()))
            return result, bytes(data)
        except (TimeoutError, subprocess.TimeoutExpired):
            notify_timeout(on_timeout, child)
            raise
        finally:
            selector.close(); child.stdout.close(); child.stderr.close()
            if child.poll() is None:
                child.kill()
                try: child.wait(timeout=2)
                except subprocess.TimeoutExpired: pass


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0: raise TimeoutError()
    return left


def read_helper_ready(helper, deadline, *, on_timeout=None):
    expected = ('HELPER_READY ' + str(helper.pid) + '\n').encode()
    data = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(helper.stdout, selectors.EVENT_READ)
    try:
        while bytes(data) != expected:
            events = selector.select(remaining(deadline))
            if not events: raise TimeoutError()
            part = os.read(helper.stdout.fileno(), len(expected) + 1 - len(data))
            if not part: raise ValueError('helper_early_exit')
            data.extend(part)
            if not expected.startswith(bytes(data)): raise ValueError('helper_ready_invalid')
        if helper.poll() is not None: raise ValueError('helper_early_exit')
    except (TimeoutError, subprocess.TimeoutExpired):
        notify_timeout(on_timeout, helper)
        raise
    finally: selector.close()


def usdt_command(probe, phase):
    if type(probe) is not usdt.ProbeIdentity or phase not in ('observe', 'compile', 'fire'):
        raise ValueError('invalid_usdt_probe')
    clause = probe.selector + probe.predicate
    if phase == 'compile': return ['/usr/sbin/dtrace', '-w', '-e', '-n', clause + '{ panic(); }']
    program = 'dtrace:::BEGIN { printf("READY\\n"); } ' + clause
    if phase == 'fire':
        return ['/usr/sbin/dtrace', '-w', '-q', '-x', 'switchrate=10hz', '-n', program + '{ panic(); }']
    program += '{ printf("HIT %d %s %s %s %s %016llx\\n", pid, probeprov, probemod, probefunc, probename, arg0); exit(0); }'
    return ['/usr/sbin/dtrace', '-q', '-x', 'switchrate=10hz', '-n', program]


def list_usdt_probe(helper, nonce, directory, label, deadline, *, env=None, on_timeout=None, facts=None, run_command=command):
    probe = usdt.ProbeSpec(nonce).bind(helper.pid)
    code, raw = run_command(['/usr/sbin/dtrace', '-l', '-n', probe.selector], directory, label,
                        remaining(deadline), env=env, on_timeout=on_timeout)
    if facts is not None:
        facts.update(list_exit=code, list_stderr=stderr_kind((directory / (label + '.stderr')).read_bytes()))
    if code: raise ValueError('probe_unavailable')
    usdt.parse_listing(raw, probe)
    if helper.poll() is not None: raise ValueError('helper_early_exit')
    if facts is not None: facts['list_status'] = 'matched'
    return probe


def _reap_usdt(child):
    if child is None: return
    try:
        if child.poll() is None: child.kill()
        child.wait(timeout=2)
    finally:
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None: stream.close()


def _observe_usdt(binary, nonce, directory, facts, *, env=None, on_timeout=None, deadline=None, run_command=command, start_tracer=subprocess.Popen):
    deadline = min(deadline if deadline is not None else float('inf'), time.monotonic() + 20)
    remaining(deadline)
    helper = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    tracer = None
    data = bytearray(); err_data = bytearray(); released = False
    try:
        read_helper_ready(helper, deadline, on_timeout=on_timeout)
        probe = list_usdt_probe(helper, nonce, directory, 'listing', deadline, env=env, on_timeout=on_timeout, facts=facts, run_command=run_command)
        with open_private(directory / 'trace.stdout') as log, open_private(directory / 'trace.stderr') as errors:
            remaining(deadline)
            tracer = start_tracer(usdt_command(probe, 'observe'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            selector = selectors.DefaultSelector()
            selector.register(tracer.stdout, selectors.EVENT_READ, log)
            selector.register(tracer.stderr, selectors.EVENT_READ, errors)
            total = 0
            try:
                while selector.get_map():
                    events = selector.select(remaining(deadline))
                    if not events: raise TimeoutError()
                    for key, _ in events:
                        part = os.read(key.fd, 4096)
                        if not part:
                            selector.unregister(key.fileobj); continue
                        total += len(part)
                        if total > LIMIT: raise ValueError('output_limit')
                        key.data.write(part); key.data.flush()
                        if key.fileobj is tracer.stdout: data.extend(part)
                        else: err_data.extend(part)
                        if not released and key.fileobj is tracer.stdout:
                            if not b'READY\n'.startswith(bytes(data)): raise ValueError('ready_invalid')
                            if bytes(data) == b'READY\n':
                                if tracer.poll() is not None or helper.poll() is not None: raise ValueError('child_early_exit')
                                if os.write(helper.stdin.fileno(), b'G') != 1: raise ValueError('release_invalid')
                                released = True
                                helper.stdin.close()
                tracer_code = tracer.wait(timeout=remaining(deadline))
                helper_code = helper.wait(timeout=remaining(deadline))
                if not released or tracer_code != 0 or helper_code != 0: raise ValueError('probe_not_observed')
                lines = bytes(data).splitlines(keepends=True)
                if len(lines) != 3 or lines[0] != b'READY\n' or lines[2] != b'\n': raise ValueError('probe_not_observed')
                usdt.parse_hit(lines[1], probe)
                facts.update(provider_exact=True, function_exact=True, name_exact=True)
            except (TimeoutError, subprocess.TimeoutExpired):
                notify_timeout(on_timeout, tracer)
                raise
            finally: selector.close()
        return True
    finally:
        facts.update(ready_count=bytes(data).splitlines().count(b'READY'),
                     hit_count=sum(line.startswith(b'HIT ') for line in bytes(data).splitlines()), released=released,
                     tracer_exit=tracer.poll() if tracer is not None else None, helper_exit=helper.poll(), trace_stderr=stderr_kind(bytes(err_data)))
        failed = sys.exc_info()[0] is not None
        cleanup_error = None
        for child in (tracer, helper):
            try: _reap_usdt(child)
            except (OSError, subprocess.SubprocessError) as error: cleanup_error = error
        if cleanup_error is not None and not failed: raise cleanup_error


def _compile_usdt(binary, nonce, directory, *, env=None, on_timeout=None, deadline=None, run_command=command):
    deadline = min(deadline if deadline is not None else float('inf'), time.monotonic() + 20)
    remaining(deadline)
    helper = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    try:
        read_helper_ready(helper, deadline, on_timeout=on_timeout)
        probe = list_usdt_probe(helper, nonce, directory, 'compile-listing', deadline, env=env, on_timeout=on_timeout, run_command=run_command)
        code, _ = run_command(usdt_command(probe, 'compile'), directory, 'panic-compile', remaining(deadline), env=env, on_timeout=on_timeout)
        if helper.poll() is not None: raise ValueError('helper_early_exit')
        return code == 0
    finally:
        failed = sys.exc_info()[0] is not None
        try: _reap_usdt(helper)
        except (OSError, subprocess.SubprocessError):
            if not failed: raise


def guard(directory):
    env = os.environ
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'Code-Hex/vz-ci-test',
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'RUNNER_ENVIRONMENT': 'github-hosted'}
    if (os.geteuid() != 0 or sys.platform != 'darwin' or os.uname().machine != 'x86_64' or
            any(env.get(k) != v for k, v in expected.items()) or
            not re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', '')) or
            not re.fullmatch(r'[1-9][0-9]{0,4}', env.get('GITHUB_RUN_ATTEMPT', '')) or
            not re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', ''))): return False
    probes = [(['/usr/sbin/sysctl', '-n', 'kern.uuid'], UUID),
              (['/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present'], '1')]
    for i, (argv, expected_value) in enumerate(probes):
        code, out = command(argv, directory, 'guard' + str(i), 5)
        if code != 0 or out.decode('ascii').strip() != expected_value: return False
    return True


def observe(binary, nonce, directory, facts, *, env=None, on_timeout=None, control_kind='pid-v1', deadline=None):
    validate_control_kind(control_kind)
    if control_kind == 'usdt-v1': return _observe_usdt(binary, nonce, directory, facts, env=env, on_timeout=on_timeout, deadline=deadline)
    name = 'vz_nonce_' + nonce
    helper = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    tracer = None
    try:
        code, listing = command(['/usr/sbin/dtrace', '-p', str(helper.pid), '-l', '-n', 'pid$target::' + name + ':entry'], directory, 'listing', env=env, on_timeout=on_timeout)
        facts['list_exit'] = code
        facts['list_status'] = parse_probe_list(listing.decode('utf-8', 'replace'), helper.pid, name)
        facts['list_stderr'] = stderr_kind((directory / 'listing.stderr').read_bytes())
        if code or facts['list_status'] != 'matched': raise ValueError('probe_unavailable')
        with open_private(directory / 'trace.stderr') as errors, open_private(directory / 'trace.stdout') as log:
            tracer = subprocess.Popen(['/usr/sbin/dtrace', '-q', '-x', 'switchrate=10hz', '-p', str(helper.pid), '-n', probe_script(nonce, False)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            selector = selectors.DefaultSelector()
            selector.register(tracer.stdout, selectors.EVENT_READ, log)
            selector.register(tracer.stderr, selectors.EVENT_READ, errors)
            data = bytearray(); err_data = bytearray(); total = 0; deadline = time.monotonic() + 20; released = False
            try:
                while selector.get_map():
                    left = deadline - time.monotonic()
                    if left <= 0: raise TimeoutError()
                    events = selector.select(left)
                    if not events: raise TimeoutError()
                    for key, _ in events:
                        part = os.read(key.fd, 4096)
                        if not part:
                            selector.unregister(key.fileobj); continue
                        total += len(part)
                        if total > LIMIT: raise ValueError('output_limit')
                        key.data.write(part); key.data.flush()
                        if key.fileobj is tracer.stdout: data.extend(part)
                        else: err_data.extend(part)
                        if not released and [line.strip() for line in bytes(data).splitlines() if line.strip()] == [b'READY'] and data.endswith(b'\n'):
                            helper.stdin.write(b'G'); helper.stdin.flush(); helper.stdin.close(); released = True
                tracer_code = tracer.wait(timeout=max(0.1, deadline-time.monotonic()))
                helper_code = helper.wait(timeout=2) if released else helper.poll()
                if not released or tracer_code != 0 or helper_code != 0 or not events_valid(bytes(data), helper.pid, name):
                    raise ValueError('probe_not_observed')
            except (TimeoutError, subprocess.TimeoutExpired):
                notify_timeout(on_timeout, tracer)
                raise
            finally:
                facts.update(event_facts(bytes(data), helper.pid, name))
                facts.update(released=released, tracer_exit=tracer.poll(), helper_exit=helper.poll(), trace_stderr=stderr_kind(bytes(err_data)))
                selector.close(); tracer.stdout.close(); tracer.stderr.close()
        return True
    finally:
        for child in (tracer, helper):
            if child is not None and child.poll() is None:
                child.kill()
                try: child.wait(timeout=2)
                except subprocess.TimeoutExpired: pass


def compile_panic(binary, nonce, directory, *, env=None, on_timeout=None, control_kind='pid-v1', deadline=None):
    validate_control_kind(control_kind)
    if control_kind == 'usdt-v1': return _compile_usdt(binary, nonce, directory, env=env, on_timeout=on_timeout, deadline=deadline)
    helper = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        code, _ = command(['/usr/sbin/dtrace', '-w', '-e', '-p', str(helper.pid), '-n', probe_script(nonce, True)], directory, 'panic-compile', env=env, on_timeout=on_timeout)
        return code == 0
    finally:
        helper.stdin.close()
        if helper.poll() is None:
            try: helper.wait(timeout=2)
            except subprocess.TimeoutExpired:
                helper.kill(); helper.wait(timeout=2)


def main():
    os.umask(0o077)
    if len(sys.argv) != 1: return 1
    temp = Path(os.environ.get('RUNNER_TEMP', ''))
    if not temp.is_absolute(): return 1
    directory = temp / 'debug' / 'panic-source-private'
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {'status': 'failed', 'stage': 'guard', 'kernel_uuid': UUID,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'getter_source_sha256': hashlib.sha256(Path(recovery_nvram_panic.__file__).read_bytes()).hexdigest(),
              'run_id': None, 'attempt': None, 'head_sha': None}
    try:
        if not guard(directory): raise ValueError('guard_rejected')
        result.update(run_id=os.environ['GITHUB_RUN_ID'], attempt=os.environ['GITHUB_RUN_ATTEMPT'],
                      head_sha=os.environ['GITHUB_SHA'])
        nonce = secrets.token_hex(32)
        result['nonce_sha256'] = hashlib.sha256(nonce.encode()).hexdigest()
        result['stage'] = 'compile'
        source = directory / 'helper.c'; binary = directory / 'helper'
        source.write_text(helper_source(nonce))
        code, _ = command(['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-O0', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], directory, 'build')
        if code: raise ValueError('compile_failed')
        code, _ = command(['/usr/bin/codesign', '-s', '-', '-f', str(binary)], directory, 'sign')
        if code: raise ValueError('sign_failed')
        result['helper_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        result['helper_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        result['stage'] = 'probe'
        result['probe_diagnostics'] = {'list_status': 'unavailable', 'list_exit': None, 'list_stderr': 'unavailable',
                                       'ready_count': 0, 'hit_count': 0, 'nonempty_line_count': 0, 'provider_exact': None, 'function_exact': None,
                                       'name_exact': None, 'released': False, 'tracer_exit': None, 'helper_exit': None,
                                       'trace_stderr': 'unavailable'}
        observe(binary, nonce, directory, result['probe_diagnostics'])
        result['stage'] = 'panic_compile_only'
        if not compile_panic(binary, nonce, directory): raise ValueError('panic_compile_failed')
        result['panic_info_getter_status'], _ = recovery_nvram_panic.read_panic_info()
        result.update(status='passed', stage='complete', probe='exact_entry', panic='compile_only')
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
        reasons = {'guard_rejected', 'compile_failed', 'sign_failed', 'probe_unavailable',
                   'probe_not_observed', 'panic_compile_failed', 'output_limit'}
        result['reason'] = str(error) if type(error) is ValueError and str(error) in reasons else (
            'timeout' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else 'operation_failed')
    output = temp / 'debug' / 'panic-source-preflight.json'
    write_public(output, result)
    print(json.dumps(result, separators=(',', ':')), flush=True)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__': sys.exit(main())
