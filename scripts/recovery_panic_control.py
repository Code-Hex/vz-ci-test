"""Prepare and fire one PID-probe panic under an external durable ACK."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import select
import subprocess
import stat
import time

CHILD_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
MAX_OUTPUT = 65536
UUID = re.compile(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\Z')
BINDING = re.compile(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')


def validate_scope(scope):
    if (not isinstance(scope, dict) or set(scope) != {'binding', 'nonce', 'baseline', 'source_identity', 'debug_boot_uuid'} or
            not isinstance(scope['binding'], str) or not BINDING.fullmatch(scope['binding']) or
            any(not isinstance(scope[k], str) or not HEX.fullmatch(scope[k]) for k in ('nonce', 'source_identity')) or
            any(not isinstance(scope[k], str) or not UUID.fullmatch(scope[k]) for k in ('baseline', 'debug_boot_uuid')) or
            scope['baseline'].upper() == scope['debug_boot_uuid'].upper()):
        raise ValueError('scope_invalid')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_hashes():
    directory = Path(__file__).resolve().parent
    return {'control_sha256': digest(Path(__file__).read_bytes()),
            'preflight_sha256': digest((directory / 'panic-source-preflight.py').read_bytes()),
            'getter_sha256': digest((directory / 'recovery_nvram_panic.py').read_bytes())}


def load_preflight():
    path = Path(__file__).resolve().with_name('panic-source-preflight.py')
    spec = importlib.util.spec_from_file_location('recovery_private_preflight', path)
    if spec is None or spec.loader is None: raise ValueError('preflight_unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(directory, name, data, save, sync):
    save(Path(directory) / name, json.dumps(data, separators=(',', ':'), sort_keys=True).encode())
    sync(Path(directory))


def once_record(directory, name, data, sync):
    fd = os.open(Path(directory) / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(json.dumps(data, separators=(',', ':'), sort_keys=True).encode())
        stream.flush(); os.fsync(stream.fileno())
    sync(Path(directory))


def prepare(directory, nonce, save, sync):
    if not isinstance(nonce, str) or not HEX.fullmatch(nonce): raise ValueError('nonce_invalid')
    directory = Path(directory) / 'panic-control'
    os.mkdir(directory, 0o700)
    sync(directory.parent)
    p = load_preflight()
    source = p.helper_source(nonce).encode()
    save(directory / 'helper.c', source); sync(directory)
    binary = directory / 'helper'
    code, _ = p.command(['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-O0', '-Wall', '-Wextra', '-Werror', str(directory / 'helper.c'), '-o', str(binary)], directory, 'build', env=CHILD_ENV)
    if code: raise ValueError('compile_failed')
    code, _ = p.command(['/usr/bin/codesign', '-s', '-', '-f', str(binary)], directory, 'sign', env=CHILD_ENV)
    if code: raise ValueError('sign_failed')
    os.chmod(binary, 0o700)
    with binary.open('rb') as stream: os.fsync(stream.fileno())
    sync(directory)
    facts = {}
    p.observe(binary, nonce, directory, facts, env=CHILD_ENV)
    if not p.compile_panic(binary, nonce, directory, env=CHILD_ENV): raise ValueError('panic_compile_failed')
    prepared = {**source_hashes(), 'helper_source_sha256': digest(source), 'helper_sha256': digest(binary.read_bytes()),
                'nonce_sha256': digest(nonce.encode()), 'observe_status': 'passed', 'compile_status': 'passed'}
    record(directory, 'prepared.json', prepared, save, sync)
    return prepared


def validate_prepared(directory, nonce, prepared):
    if not isinstance(prepared, dict): raise ValueError('prepared_invalid')
    directory = Path(directory) / 'panic-control'
    expected = {**source_hashes(), 'helper_source_sha256': digest(load_preflight().helper_source(nonce).encode()),
                'helper_sha256': digest((directory / 'helper').read_bytes()), 'nonce_sha256': digest(nonce.encode()),
                'observe_status': 'passed', 'compile_status': 'passed'}
    if prepared != expected or json.loads((directory / 'prepared.json').read_text()) != prepared:
        raise ValueError('prepared_invalid')
    if digest((directory / 'helper.c').read_bytes()) != prepared['helper_source_sha256']:
        raise ValueError('prepared_invalid')
    return directory / 'helper'


def release_after_ack(helper, on_ready, facts, current_boot_uuid, expected_boot, before_write):
    if on_ready(facts) is not True: return 'not_released'
    if current_boot_uuid().upper() != expected_boot.upper(): return 'not_released'
    try:
        before_write()
        return 'released' if os.write(helper.stdin.fileno(), b'G') == 1 else 'unknown'
    except BaseException:
        return 'unknown'


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


def wait_same_children(tracer, helper, directory, *, interval=30, initial_bytes=0,
                       selector_factory=selectors.DefaultSelector, on_fault=lambda code: None, read_fn=os.read,
                       fallback_select=select.select):
    streams = {}; nonblocking = set(); logs = []; selector = None
    total = initial_bytes; overflow = False; intervals = 0; faults = 0
    next_interval = time.monotonic() + interval
    def fault():
        nonlocal faults
        faults += 1
        try: on_fault(1)
        except BaseException: pass
    try:
        selector = selector_factory()
    except BaseException:
        fault()
    for label, child in (('tracer', tracer), ('helper', helper)):
        for channel in ('stdout', 'stderr'):
            stream = getattr(child, channel)
            if stream is None: continue
            path = Path(directory) / (label + '.' + channel)
            try:
                log = open_private(path, append=True); logs.append(log)
            except BaseException:
                log = None; overflow = True; fault()
            streams[stream] = log
            try:
                os.set_blocking(stream.fileno(), False); nonblocking.add(stream)
            except BaseException: fault()
            if selector is not None:
                try: selector.register(stream, selectors.EVENT_READ)
                except BaseException:
                    fault()
                    try: selector.close()
                    except BaseException: fault()
                    selector = None
    exit_codes = [None, None]
    while True:
        try:
            now = time.monotonic()
            if now >= next_interval:
                intervals += 1; next_interval = now + interval
            for i, child in enumerate((tracer, helper)):
                if exit_codes[i] is None and child.poll() is not None:
                    try: exit_codes[i] = child.wait(timeout=0)
                    except BaseException: fault()
            if all(code is not None for code in exit_codes) and not streams:
                break
            timeout = min(interval, 0.25)
            if selector is not None:
                try:
                    events = [key.fileobj for key, _ in selector.select(timeout)]
                except BaseException:
                    fault()
                    try: selector.close()
                    except BaseException: fault()
                    selector = None
                    continue
            elif streams:
                try: events = fallback_select(list(streams), [], [], timeout)[0]
                except BaseException:
                    fault()
                    events = [stream for stream in streams if stream in nonblocking]
                    if not events and all(code is not None for code in exit_codes): break
                    try: time.sleep(min(timeout, 0.05))
                    except BaseException: fault()
            else:
                try: time.sleep(timeout)
                except BaseException: fault()
                events = []
            for stream in events:
                try: part = read_fn(stream.fileno(), 4096)
                except BlockingIOError:
                    continue
                except InterruptedError:
                    fault(); continue
                except BaseException:
                    fault()
                    if all(code is not None for code in exit_codes):
                        if selector is not None:
                            try: selector.unregister(stream)
                            except BaseException: fault()
                        streams.pop(stream, None)
                    continue
                if not part:
                    if selector is not None:
                        try: selector.unregister(stream)
                        except BaseException:
                            fault()
                            try: selector.close()
                            except BaseException: fault()
                            selector = None
                    streams.pop(stream, None); continue
                available = max(0, MAX_OUTPUT - total)
                if len(part) > available and not overflow:
                    overflow = True; fault()
                log = streams[stream]
                if available and log is not None:
                    try: log.write(part[:available]); log.flush()
                    except BaseException:
                        overflow = True; streams[stream] = None; fault()
                total += len(part)
        except BaseException:
            fault()
    if selector is not None:
        try: selector.close()
        except BaseException: fault()
    for log in logs:
        try: log.close()
        except BaseException: fault()
    for child in (tracer, helper):
        for channel in ('stdout', 'stderr'):
            stream = getattr(child, channel)
            if stream is not None:
                try: stream.close()
                except BaseException: fault()
    return {'tracer_exit': exit_codes[0], 'helper_exit': exit_codes[1], 'wait_intervals': intervals,
            'output_overflow': overflow, 'ownership_faults': faults}


def fire(directory, scope, prepared, save, sync, on_ready, current_boot_uuid):
    validate_scope(scope)
    binary = validate_prepared(directory, scope['nonce'], prepared)
    if current_boot_uuid().upper() != scope['debug_boot_uuid'].upper(): raise ValueError('boot_mismatch')
    private = Path(directory) / 'panic-control'
    once_record(private, 'intent.json', {'scope': scope, 'prepared': prepared}, sync)
    helper = tracer = None
    attempted = False
    total = 0
    def note_unknown(code):
        try: once_record(private, 'ownership-unknown.json', {'code': 1}, sync)
        except BaseException: pass
    try:
        helper = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CHILD_ENV)
        probe = 'pid$target::vz_nonce_' + scope['nonce'] + ':entry'
        program = 'dtrace:::BEGIN { printf("READY\\n"); } ' + probe + ' { panic(); }'
        tracer = subprocess.Popen(['/usr/sbin/dtrace', '-w', '-q', '-x', 'switchrate=10hz', '-p', str(helper.pid), '-n', program],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CHILD_ENV)
        selector = selectors.DefaultSelector()
        selector.register(tracer.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(tracer.stderr, selectors.EVENT_READ, 'stderr')
        total = 0; data = bytearray(); deadline = time.monotonic() + 20
        try:
            with open_private(private / 'tracer.stdout') as out, open_private(private / 'tracer.stderr') as err:
                while bytes(data) != b'READY\n':
                    left = deadline - time.monotonic()
                    if left <= 0: raise TimeoutError()
                    events = selector.select(left)
                    if not events: raise TimeoutError()
                    for key, _ in events:
                        part = os.read(key.fd, 4096)
                        if not part: raise ValueError('tracer_early_exit')
                        total += len(part)
                        if total > MAX_OUTPUT: raise ValueError('output_limit')
                        (out if key.data == 'stdout' else err).write(part)
                        if key.data == 'stdout': data.extend(part)
                        if len(data) > len(b'READY\n') or not b'READY\n'.startswith(bytes(data)):
                            raise ValueError('ready_invalid')
        finally:
            selector.close()
        if tracer.poll() is not None or helper.poll() is not None: raise ValueError('child_early_exit')
        facts = {'scope': scope, 'helper_sha256': prepared['helper_sha256'], 'helper_pid': helper.pid,
                 'tracer_pid': tracer.pid, 'ready': True}
        def before_write():
            nonlocal attempted
            attempted = True
            once_record(private, 'release-attempt.json', facts, sync)
        def ready_ack(value):
            return on_ready(value) is True and tracer.poll() is None and helper.poll() is None
        released = release_after_ack(helper, ready_ack, facts, current_boot_uuid, scope['debug_boot_uuid'], before_write)
        if released == 'not_released': return {'phase': 'not_released', 'release_status': released}
        attempted = True
        if released == 'unknown': note_unknown(1)
        result = wait_same_children(tracer, helper, private, initial_bytes=total, on_fault=note_unknown)
        return {'phase': 'returned' if released == 'released' and not result['output_overflow'] and not result['ownership_faults'] else 'unknown',
                'release_status': released, **result}
    except BaseException:
        if not attempted: raise
        note_unknown(1)
        while True:
            try:
                result = wait_same_children(tracer, helper, private, initial_bytes=total, on_fault=note_unknown)
                return {'phase': 'unknown', 'release_status': 'unknown', **result}
            except BaseException:
                note_unknown(1)
    finally:
        if not attempted:
            for child in (tracer, helper):
                if child is not None and child.poll() is None:
                    child.kill()
                    try: child.wait(timeout=2)
                    except subprocess.TimeoutExpired: pass
