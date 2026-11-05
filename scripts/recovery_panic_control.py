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


class PrepareProgress:
    STAGES = frozenset(('setup', 'build', 'sign', 'verify_signature', 'verify_build', 'observe', 'compile_panic', 'receipt'))
    ENUMS = {'list_status': frozenset(('unavailable', 'matched', 'ambiguous', 'missing')),
             'list_stderr': frozenset(('unavailable', 'empty', 'permission', 'attach_failed', 'no_probes', 'compile_failed', 'other')),
             'trace_stderr': frozenset(('unavailable', 'empty', 'permission', 'attach_failed', 'no_probes', 'compile_failed', 'other'))}
    BOOLS = frozenset(('provider_exact', 'function_exact', 'name_exact', 'released'))
    COUNTS = frozenset(('ready_count', 'hit_count'))
    EXITS = frozenset(('list_exit', 'tracer_exit', 'helper_exit'))

    def __init__(self, directory, save, sync, facts, *, failure_file='prepare-failure.json'):
        self.directory, self.save, self.sync, self.facts = directory, save, sync, facts
        self.failure_file = failure_file
        self.stage = 'setup'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None: return False
        if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
            kind = 'timeout'
        elif isinstance(exc, OSError):
            kind = 'os_error'
        elif isinstance(exc, ValueError):
            kind = 'rejected'
        else:
            kind = 'other'
        observed = {}
        for key, value in self.facts.items():
            if key in self.ENUMS and isinstance(value, str) and value in self.ENUMS[key]: observed[key] = value
            elif key in self.BOOLS and (type(value) is bool or value is None): observed[key] = value
            elif key in self.COUNTS and type(value) is int and 0 <= value <= 65536: observed[key] = value
            elif key in self.EXITS and (value is None or type(value) is int and -255 <= value <= 255): observed[key] = value
        try:
            record(self.directory, self.failure_file, {'stage': self.stage if self.stage in self.STAGES else 'setup',
                                                           'kind': kind, 'observe': observed}, self.save, self.sync)
        except BaseException:
            pass
        return False


def read_private(path, mode, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != mode or info.st_size > maximum):
            raise ValueError('private_file_invalid')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if len(data) != info.st_size or (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_size):
            raise ValueError('private_file_changed')
        return data


def build(directory, nonce, save, sync):
    if not isinstance(nonce, str) or not HEX.fullmatch(nonce): raise ValueError('nonce_invalid')
    directory = Path(directory) / 'panic-control'
    os.mkdir(directory, 0o700)
    with PrepareProgress(directory, save, sync, {}, failure_file='build-failure.json') as progress:
        sync(directory.parent)
        p = load_preflight()
        source = p.helper_source(nonce).encode()
        save(directory / 'helper.c', source); sync(directory)
        binary = directory / 'helper'
        progress.stage = 'build'
        code, _ = p.command(['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-O0', '-Wall', '-Wextra', '-Werror', str(directory / 'helper.c'), '-o', str(binary)], directory, 'build', env=CHILD_ENV)
        if code: raise ValueError('compile_failed')
        progress.stage = 'sign'
        code, _ = p.command(['/usr/bin/codesign', '-s', '-', '-f', str(binary)], directory, 'sign', env=CHILD_ENV)
        if code: raise ValueError('sign_failed')
        progress.stage = 'verify_signature'
        code, _ = p.command(['/usr/bin/codesign', '--verify', '--strict', str(binary)], directory, 'verify-signature', env=CHILD_ENV)
        if code: raise ValueError('signature_invalid')
        os.chmod(binary, 0o700)
        with binary.open('rb') as stream: os.fsync(stream.fileno())
        sync(directory)
        progress.stage = 'receipt'
        built = {**source_hashes(), 'helper_source_sha256': digest(source), 'helper_sha256': digest(read_private(binary, 0o700, 16 * 1024 * 1024)),
                 'nonce_sha256': digest(nonce.encode()), 'build_status': 'passed', 'sign_status': 'passed', 'signature_status': 'verified'}
        record(directory, 'built.json', built, save, sync)
        return built


def validate_built(directory, nonce):
    if not isinstance(nonce, str) or not HEX.fullmatch(nonce): raise ValueError('nonce_invalid')
    directory = Path(directory) / 'panic-control'
    p = load_preflight()
    source = read_private(directory / 'helper.c', 0o600, 1024 * 1024)
    binary = read_private(directory / 'helper', 0o700, 16 * 1024 * 1024)
    built = json.loads(read_private(directory / 'built.json', 0o600, 65536))
    expected = {**source_hashes(), 'helper_source_sha256': digest(p.helper_source(nonce).encode()),
                'helper_sha256': digest(binary), 'nonce_sha256': digest(nonce.encode()),
                'build_status': 'passed', 'sign_status': 'passed', 'signature_status': 'verified'}
    if built != expected or digest(source) != expected['helper_source_sha256']: raise ValueError('built_invalid')
    return built


def _timeout_command(argv, directory, label, budget, timeout):
    output = open_private(Path(directory) / ('timeout-' + label + '.stdout'))
    try:
        errors = open_private(Path(directory) / ('timeout-' + label + '.stderr'))
    except BaseException:
        output.close()
        raise
    child = None
    selector = selectors.DefaultSelector()
    try:
        if budget == 0: return 'limit', budget
        try:
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CHILD_ENV)
        except OSError:
            return 'unavailable', budget
        selector.register(child.stdout, selectors.EVENT_READ, output)
        selector.register(child.stderr, selectors.EVENT_READ, errors)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0: return 'timeout', budget
            events = selector.select(remaining)
            if not events: return 'timeout', budget
            for key, _ in events:
                data = os.read(key.fd, 4096)
                if not data:
                    selector.unregister(key.fileobj); continue
                if len(data) > budget:
                    if budget: key.data.write(data[:budget])
                    return 'limit', 0
                key.data.write(data); budget -= len(data)
        try:
            code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return 'timeout', budget
        return ('ok' if code == 0 else 'failed'), budget
    finally:
        selector.close(); output.close(); errors.close()
        if child is not None:
            if child.poll() is None:
                child.kill()
                try: child.wait(timeout=0.2)
                except subprocess.TimeoutExpired: pass
            if child.stdout is not None: child.stdout.close()
            if child.stderr is not None: child.stderr.close()


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def capture_timeout(target, directory, *, sync=_sync_directory):
    directory = Path(directory)
    budget = 65536
    ps_status = spindump_status = 'unavailable'
    if target.poll() is None:
        ps_status, budget = _timeout_command(['/bin/ps', '-p', str(target.pid), '-o', 'pid=,state=,wchan=,comm=,etime=,time=,pcpu='],
                                             directory, 'ps', budget, 2)
    if target.poll() is None:
        spindump_status, budget = _timeout_command(['/usr/sbin/spindump', str(target.pid), '1', '10',
            '-onlyTarget', '-noSymbolicate', '-noBinary', '-noFile'], directory, 'spindump', budget, 3)
    once_record(directory, 'timeout-diagnostic.json', {'ps_status': ps_status, 'profiler': 'spindump', 'spindump_status': spindump_status,
                                                       'bytes_captured': 65536 - budget}, sync)


def prepare(directory, nonce, save, sync, *, observe=None, compile_only=None):
    private = Path(directory) / 'panic-control'
    facts = {'list_status': 'unavailable', 'list_exit': None, 'list_stderr': 'unavailable',
             'ready_count': 0, 'hit_count': 0, 'provider_exact': None, 'function_exact': None,
             'name_exact': None, 'released': False, 'tracer_exit': None, 'helper_exit': None,
             'trace_stderr': 'unavailable'}
    with PrepareProgress(private, save, sync, facts) as progress:
        progress.stage = 'verify_build'
        built = validate_built(directory, nonce)
        p = load_preflight()
        observe = p.observe if observe is None else observe
        compile_only = p.compile_panic if compile_only is None else compile_only
        binary = private / 'helper'
        progress.stage = 'observe'
        on_timeout = lambda child: capture_timeout(child, private, sync=sync)
        observe(binary, nonce, private, facts, env=CHILD_ENV, on_timeout=on_timeout)
        progress.stage = 'compile_panic'
        if not compile_only(binary, nonce, private, env=CHILD_ENV, on_timeout=on_timeout): raise ValueError('panic_compile_failed')
        progress.stage = 'receipt'
        prepared = {key: built[key] for key in ('control_sha256', 'preflight_sha256', 'getter_sha256',
                                                 'helper_source_sha256', 'helper_sha256', 'nonce_sha256')}
        prepared.update(observe_status='passed', compile_status='passed')
        record(private, 'prepared.json', prepared, save, sync)
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
