"""Measure the bounded profiler on one owned, waiting Python process."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import sys
import tempfile

import recovery_panic_control as control
import recovery_reports as reports


def start_target():
    source = 'import os,sys; os.write(1,b"READY\\n"); sys.exit(0 if sys.stdin.buffer.read(1)==b"G" else 2)'
    return subprocess.Popen([sys.executable, '-c', source], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=control.CHILD_ENV, start_new_session=True)


def stop_target(child):
    try:
        if child.poll() is None: os.write(child.stdin.fileno(), b'G')
        return 'reaped' if child.wait(timeout=3) == 0 else 'failed'
    except (OSError, subprocess.SubprocessError):
        child.kill()
        try: child.wait(timeout=2); return 'forced'
        except subprocess.TimeoutExpired: return 'failed'
    finally:
        for stream in (child.stdin, child.stdout):
            if stream is not None: stream.close()


def report_status(status, data, pid):
    if status != 'ok' or not isinstance(data, bytes) or not 0 < len(data) <= 65536 or type(pid) is not int or not 0 < pid < 2**31:
        return 'unverified'
    pids = re.findall(rb'(?m)^(?:PID:[ \t]*|Process:[^\r\n]{1,256}?\[)([1-9][0-9]*)(?:\][^\r\n]*)?[ \t]*\r?$', data)
    thread = re.search(rb'(?m)^[ \t]*Thread[ \t]+(?:0x[0-9a-fA-F]+|[0-9]+)\b', data)
    frame = re.search(rb'(?m)^[ \t]+[0-9]+[ \t]+[^\r\n]*\[0x[0-9a-fA-F]+\]', data)
    return 'verified' if pids and all(int(value) == pid for value in pids) and thread and frame else 'unverified'


def public_summary(state):
    result = {'status': 'failed', 'profiler': 'spindump', 'context': {}, 'sources': {},
              'cleanup': state.get('cleanup') if state.get('cleanup') in ('not_started', 'reaped', 'forced', 'failed') else 'failed',
              'report_status': 'verified' if state.get('report_status') == 'verified' else 'unverified'}
    for key, pattern in (('run_id', r'[1-9][0-9]{0,19}'), ('attempt', r'[1-9][0-9]{0,4}'), ('head_sha', r'[0-9a-f]{40}')):
        value = state.get('context', {}).get(key)
        if isinstance(value, str) and re.fullmatch(pattern, value): result['context'][key] = value
    for key in ('preflight_sha256', 'control_sha256', 'guard_sha256', 'reports_sha256'):
        value = state.get('sources', {}).get(key)
        if isinstance(value, str) and control.HEX.fullmatch(value): result['sources'][key] = value
    envelope = state.get('envelope', {})
    try:
        cipher = envelope['ciphertext']
        raw = base64.b64decode(cipher, validate=True) if isinstance(cipher, str) and len(cipher) <= 58000 else b''
        if not raw or hashlib.sha256(raw).hexdigest() != envelope['cipher_sha256'] or not control.HEX.fullmatch(envelope['cert_fingerprint']):
            raise ValueError('envelope_invalid')
        result['envelope'] = {key: envelope[key] for key in ('ciphertext', 'cipher_sha256', 'cert_fingerprint')}
    except (ValueError, KeyError, TypeError):
        return result
    if (state.get('status') in ('passed', 'unverified') and result['cleanup'] == 'reaped'
            and len(result['context']) == 3 and len(result['sources']) == 4):
        result['status'] = 'passed' if result['report_status'] == 'verified' else 'unverified'
    return result


def main():
    temp = Path(os.environ.get('RUNNER_TEMP', ''))
    if len(sys.argv) != 1 or os.geteuid() != 0 or not temp.is_absolute() or not temp.is_dir():
        print('{"event":"profiler_preflight","status":"failed"}', flush=True)
        return 1
    private = Path(tempfile.mkdtemp(prefix='profiler-preflight-', dir=temp))
    state = {'status': 'failed', 'cleanup': 'not_started', 'report_status': 'unverified',
             'context': {'run_id': os.getenv('GITHUB_RUN_ID', ''), 'attempt': os.getenv('GITHUB_RUN_ATTEMPT', ''),
                         'head_sha': os.getenv('GITHUB_SHA', '')}, 'sources': {}}
    child = diagnostic = report = None
    nonce = secrets.token_hex(32)
    cert = os.getenv('PROFILER_REPORT_CERT', '').encode()
    fingerprint = None
    guard = control.load_preflight()
    try:
        state['sources'] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in (
            ('preflight_sha256', __file__), ('control_sha256', control.__file__),
            ('guard_sha256', guard.__file__), ('reports_sha256', reports.__file__))}
        if private.stat().st_uid != 0 or private.stat().st_mode & 0o777 != 0o700 or not guard.guard(private):
            raise ValueError('guard_rejected')
        if b'-----BEGIN CERTIFICATE-----' not in cert or len(cert) > 32768:
            raise ValueError('certificate_required')
        fingerprint = reports.cert_fingerprint(cert)
        child = start_target()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            if not selector.select(5) or os.read(child.stdout.fileno(), 7) != b'READY\n' or child.poll() is not None:
                raise ValueError('owned_child_not_ready')
        control.capture_timeout(child, private)
        if child.poll() is not None: raise ValueError('owned_child_exited')
        diagnostic = json.loads(control.read_private(private / 'timeout-diagnostic.json', 0o600, 4096))
        report = control.read_private(private / 'timeout-spindump.stdout', 0o600, 65536)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    finally:
        if child is not None:
            state['cleanup'] = stop_target(child)
    if state['cleanup'] == 'reaped' and isinstance(diagnostic, dict) and report is not None:
        state['report_status'] = report_status(diagnostic.get('spindump_status'), report, child.pid)
        state['status'] = 'unverified'
    if fingerprint is not None:
        try:
            fragments, budget = {}, 65536
            names = ('timeout-diagnostic.json', 'timeout-spindump.stdout', 'timeout-spindump.stderr', 'timeout-ps.stdout', 'timeout-ps.stderr')
            for name in names:
                try: raw = control.read_private(private / name, 0o600, 65536)
                except FileNotFoundError: continue
                fragments[name] = base64.b64encode(raw[:budget]).decode()
                budget -= min(len(raw), budget)
            metadata = {'kind': 'profiler_preflight', **state['context'], 'sources': state['sources'],
                        'nonce': nonce, 'target_pid': child.pid if child is not None else None}
            state['envelope'] = reports.encrypt_bundle(cert, metadata, json.dumps(fragments).encode())
            if state['envelope']['cert_fingerprint'] != fingerprint: raise ValueError('certificate_changed')
        except (OSError, ValueError, subprocess.SubprocessError):
            state.pop('envelope', None)
            state['status'] = 'failed'
    summary = public_summary(state)
    output = temp / 'debug' / 'profiler-preflight.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink(): raise ValueError('public_directory_invalid')
    guard.write_public(output, summary)
    print(json.dumps({'event': 'profiler_preflight', 'status': summary['status']}), flush=True)
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
