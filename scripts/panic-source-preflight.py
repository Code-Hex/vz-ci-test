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
import sys
import time

import recovery_nvram_panic

UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
LIMIT = 65536


def helper_source(nonce):
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
    lines = data.splitlines()
    if len(lines) != 2 or lines[0] != b'READY': return False
    pattern = rb'HIT pid' + str(pid).encode() + rb':[A-Za-z0-9_.+-]+:' + re.escape(name.encode()) + rb':entry'
    return bool(re.fullmatch(pattern, lines[1]))


def command(argv, directory, label, timeout=15):
    with (directory / (label + '.stdout')).open('wb') as sink, (directory / (label + '.stderr')).open('wb') as errors:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        finally:
            selector.close(); child.stdout.close(); child.stderr.close()
            if child.poll() is None:
                child.kill()
                try: child.wait(timeout=2)
                except subprocess.TimeoutExpired: pass


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


def observe(binary, nonce, directory):
    name = 'vz_nonce_' + nonce
    helper = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tracer = None
    try:
        code, listing = command(['/usr/sbin/dtrace', '-p', str(helper.pid), '-l', '-n', 'pid$target::' + name + ':entry'], directory, 'listing')
        if code or parse_probe_list(listing.decode('utf-8', 'replace'), helper.pid, name) != 'matched': raise ValueError('probe_unavailable')
        with (directory / 'trace.stderr').open('wb') as errors, (directory / 'trace.stdout').open('wb') as log:
            tracer = subprocess.Popen(['/usr/sbin/dtrace', '-q', '-x', 'switchrate=10hz', '-p', str(helper.pid), '-n', probe_script(nonce, False)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            selector = selectors.DefaultSelector()
            selector.register(tracer.stdout, selectors.EVENT_READ, log)
            selector.register(tracer.stderr, selectors.EVENT_READ, errors)
            data = bytearray(); total = 0; deadline = time.monotonic() + 20; released = False
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
                        if not released and bytes(data).splitlines() == [b'READY'] and data.endswith(b'\n'):
                            helper.stdin.write(b'G'); helper.stdin.flush(); helper.stdin.close(); released = True
                if not released or tracer.wait(timeout=max(0.1, deadline-time.monotonic())) != 0 or helper.wait(timeout=2) != 0 or not events_valid(bytes(data), helper.pid, name):
                    raise ValueError('probe_not_observed')
            finally:
                selector.close(); tracer.stdout.close(); tracer.stderr.close()
        return True
    finally:
        for child in (tracer, helper):
            if child is not None and child.poll() is None:
                child.kill()
                try: child.wait(timeout=2)
                except subprocess.TimeoutExpired: pass


def compile_panic(binary, nonce, directory):
    helper = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        code, _ = command(['/usr/sbin/dtrace', '-w', '-e', '-p', str(helper.pid), '-n', probe_script(nonce, True)], directory, 'panic-compile')
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
        observe(binary, nonce, directory)
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
    output.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    print(json.dumps(result, separators=(',', ':')), flush=True)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__': sys.exit(main())
