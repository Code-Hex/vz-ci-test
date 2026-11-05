"""Actions-only non-faulting USDT gate."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time

ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
KERNEL_UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
STAGES = ('context', 'sources', 'kernel', 'header', 'compile', 'sign', 'verify', 'helper_ready', 'listing',
          'compile_panic', 'tracer_ready', 'once', 'hit', 'returned', 'quit', 'exits', 'completed')
REASONS = ('invalid', 'command_exit', 'deadline', 'output_limit', 'child_eof', 'os_error', 'requires_root', 'cleanup_unverified', 'interrupted')
COMMANDS = ('kernel_uuid', 'kernel_file', 'header', 'compile', 'sign', 'verify', 'listing', 'panic_compile', 'helper', 'tracer')
HASHES = ('script', 'workflow', 'nonce', 'provider', 'argument', 'provider_source', 'header', 'helper_source', 'helper_binary', 'tracer_program', 'panic_program')


class GateFailure(ValueError):
    def __init__(self, reason='invalid'):
        super().__init__('usdt_gate_failed')
        self.reason = reason if reason in REASONS else 'invalid'


def require(condition):
    if not condition: raise GateFailure()


def digest(raw): return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ProbeSpec:
    nonce: str

    def __post_init__(self):
        require(type(self.nonce) is str and re.fullmatch('[0-9a-f]{64}', self.nonce))

    @property
    def provider(self): return 'vzobs' + self.nonce[:16] + 'p'

    @property
    def argument(self): return self.nonce[16:32]

    @property
    def function(self): return 'vz_nonce_' + self.nonce

    def bind(self, pid): return ProbeIdentity(self, pid)


@dataclass(frozen=True)
class ProbeIdentity:
    spec: ProbeSpec
    pid: int

    def __post_init__(self):
        require(type(self.spec) is ProbeSpec and type(self.pid) is int and 0 < self.pid < 2**31)

    @property
    def fields(self): return (self.spec.provider + str(self.pid), 'helper', self.spec.function, 'observe')

    @property
    def selector(self): return ':'.join(self.fields)

    @property
    def predicate(self): return ' /pid == ' + str(self.pid) + ' && arg0 == 0x' + self.spec.argument + '/ '


def validate_header(raw, provider):
    require(type(raw) is bytes and len(raw) <= 65536)
    try: text = raw.decode('ascii')
    except UnicodeError: raise GateFailure() from None
    require(re.search(r'^#define\s+' + re.escape(provider.upper()) + r'_OBSERVE\s*\(', text, re.M))
    return True


def parse_ready(raw, pid):
    require(type(pid) is int and pid > 0 and raw == ('HELPER_READY ' + str(pid) + '\n').encode())


def parse_listing(raw, probe):
    require(type(raw) is bytes and len(raw) <= 65536 and type(probe) is ProbeIdentity)
    try: lines = raw.decode('ascii').splitlines()
    except UnicodeError: raise GateFailure() from None
    require(lines and lines[0].split() == ['ID', 'PROVIDER', 'MODULE', 'FUNCTION', 'NAME'])
    rows, identifiers = [line.split() for line in lines[1:] if line.strip()], set()
    require(1 <= len(rows) <= 32)
    for row in rows:
        require(len(row) == 5 and re.fullmatch('[1-9][0-9]*', row[0]) and row[0] not in identifiers and
                tuple(row[1:]) == probe.fields)
        identifiers.add(row[0])
    return len(rows)


def parse_hit(raw, probe):
    require(type(probe) is ProbeIdentity and type(raw) is bytes)
    expected = 'HIT ' + str(probe.pid) + ' ' + ' '.join(probe.fields) + ' ' + probe.spec.argument + '\n'
    require(raw == expected.encode())


def tracer_command(probe):
    require(type(probe) is ProbeIdentity)
    program = ('dtrace:::BEGIN { printf("TRACER_READY\\n"); } ' + probe.selector + probe.predicate +
               '{ printf("HIT %d %s %s %s %s %016llx\\n", pid, probeprov, probemod, probefunc, probename, arg0); exit(0); }')
    return ['/usr/sbin/dtrace', '-q', '-x', 'switchrate=10hz', '-n', program]


def panic_compile_command(probe):
    require(type(probe) is ProbeIdentity)
    return ['/usr/sbin/dtrace', '-w', '-e', '-n', probe.selector + probe.predicate + '{ panic(); }']


def initial_report():
    return {'scope': 'userspace_usdt_non_faulting', 'status': 'failed', 'stage': 'context', 'reason': None,
            'context': None, 'system': None, 'machine': None, 'root': False, 'kernel_matched': False,
            'hashes': {}, 'commands': {}, 'helper_pid': None, 'tracer_pid': None, 'listing_rows': 0,
            'o_attempts': 0, 'o_written': False, 'q_written': False, 'hit_count': 0,
            'helper_returned': False, 'cleanup': 'not_started'}


def public_report(value):
    require(type(value) is dict and set(value) == set(initial_report()))
    require(value['scope'] == 'userspace_usdt_non_faulting' and value['status'] in ('passed', 'failed') and value['stage'] in STAGES and
            value['reason'] in (None,) + REASONS and value['cleanup'] in ('not_started', 'reaped', 'unverified') and
            value['system'] in (None, 'Darwin', 'other') and value['machine'] in (None, 'arm64', 'x86_64', 'other'))
    for key in ('root', 'kernel_matched', 'o_written', 'q_written', 'helper_returned'): require(type(value[key]) is bool)
    for key in ('helper_pid', 'tracer_pid'): require(value[key] is None or type(value[key]) is int and value[key] > 0)
    for key, limit in (('listing_rows', 32), ('o_attempts', 1), ('hit_count', 1)):
        require(type(value[key]) is int and 0 <= value[key] <= limit)
    require(type(value['hashes']) is dict and set(value['hashes']) <= set(HASHES) and
            all(type(item) is str and re.fullmatch('[0-9a-f]{64}', item) for item in value['hashes'].values()))
    require(type(value['commands']) is dict and set(value['commands']) <= set(COMMANDS))
    for item in value['commands'].values():
        require(type(item) is dict and set(item) == {'exit', 'stdout_bytes', 'stderr_bytes', 'stdout_sha256', 'stderr_sha256', 'output_complete'})
        require(item['exit'] is None or type(item['exit']) is int and -255 <= item['exit'] <= 255)
        require(type(item['output_complete']) is bool)
        require(all(type(item[key]) is int and 0 <= item[key] <= 65536 for key in ('stdout_bytes', 'stderr_bytes')))
        require(all(type(item[key]) is str and re.fullmatch('[0-9a-f]{64}', item[key]) for key in ('stdout_sha256', 'stderr_sha256')))
    if value['context'] is not None: validate_context_record(value['context'])
    if value['status'] == 'passed':
        require(value['stage'] == 'completed' and value['reason'] is None and value['root'] and value['kernel_matched'] and
                value['system'] == 'Darwin' and value['machine'] == 'x86_64' and value['context'] is not None and
                set(value['hashes']) == set(HASHES) and set(value['commands']) == set(COMMANDS) and
                all(item['exit'] == 0 and item['output_complete'] for item in value['commands'].values()) and
                type(value['helper_pid']) is int and type(value['tracer_pid']) is int and value['helper_pid'] != value['tracer_pid'] and
                value['listing_rows'] > 0 and value['o_attempts'] == value['hit_count'] == 1 and value['o_written'] and
                value['q_written'] and value['helper_returned'] and value['cleanup'] == 'reaped')
    return json.loads(json.dumps(value, sort_keys=True))


def validate_context_record(value):
    require(type(value) is dict and set(value) == {'run', 'attempt', 'sha', 'repository', 'ref', 'event', 'runner_environment'})
    require(type(value['run']) is str and re.fullmatch('[1-9][0-9]{0,19}', value['run']) and
            type(value['attempt']) is str and re.fullmatch('[1-9][0-9]{0,4}', value['attempt']) and
            type(value['sha']) is str and re.fullmatch('[0-9a-f]{40}', value['sha']) and
            value['repository'] == 'Code-Hex/vz-ci-test' and value['ref'] == 'refs/heads/main' and
            value['event'] == 'workflow_dispatch' and value['runner_environment'] == 'github-hosted')


def checked_context(env):
    require(env.get('GITHUB_ACTIONS') == 'true')
    value = {key: env.get(name) for key, name in (('run', 'GITHUB_RUN_ID'), ('attempt', 'GITHUB_RUN_ATTEMPT'), ('sha', 'GITHUB_SHA'),
             ('repository', 'GITHUB_REPOSITORY'), ('ref', 'GITHUB_REF'), ('event', 'GITHUB_EVENT_NAME'), ('runner_environment', 'RUNNER_ENVIRONMENT'))}
    validate_context_record(value)
    return value


class State:
    def __init__(self):
        self.report, self.deadline, self.used = initial_report(), time.monotonic() + 170, 0
        self.cleanup_ok = True

    def stage(self, name):
        require(name in STAGES)
        self.report['stage'] = name


class Child:
    def __init__(self, argv, state, *, stdin=False):
        self.state = state
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=ENV, start_new_session=True)
        self.selector, self.data, self.position = selectors.DefaultSelector(), {'stdout': bytearray(), 'stderr': bytearray()}, 0
        self.output_drained, self.interrupted = False, False
        for key in self.data:
            stream = getattr(self.process, key)
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, key)

    def pump(self, deadline):
        remaining = min(deadline, self.state.deadline) - time.monotonic()
        if remaining <= 0: raise GateFailure('deadline')
        for key, _ in self.selector.select(min(.1, remaining)):
            try: raw = os.read(key.fileobj.fileno(), 4096)
            except BlockingIOError: continue
            if not raw:
                self.selector.unregister(key.fileobj)
                if not self.selector.get_map(): self.output_drained = True
                continue
            self.state.used += len(raw)
            if self.state.used > 65536: raise GateFailure('output_limit')
            self.data[key.data].extend(raw)

    def line(self, seconds):
        deadline = min(self.state.deadline, time.monotonic() + seconds)
        while True:
            end = self.data['stdout'].find(b'\n', self.position)
            if end != -1:
                line = bytes(self.data['stdout'][self.position:end + 1])
                self.position = end + 1
                if len(line) > 4096: raise GateFailure('output_limit')
                return line
            if len(self.data['stdout']) - self.position > 4096: raise GateFailure('output_limit')
            if not self.selector.get_map(): raise GateFailure('child_eof')
            self.pump(deadline)

    def finish(self, seconds):
        deadline = min(self.state.deadline, time.monotonic() + seconds)
        while self.process.poll() is None or self.selector.get_map(): self.pump(deadline)
        return self.process.wait(timeout=max(.01, deadline - time.monotonic()))

    def facts(self):
        return {'exit': self.process.poll(), 'stdout_bytes': len(self.data['stdout']), 'stderr_bytes': len(self.data['stderr']),
                'stdout_sha256': digest(self.data['stdout']), 'stderr_sha256': digest(self.data['stderr']),
                'output_complete': self.output_drained and not self.interrupted and self.process.poll() is not None}

    def stop(self):
        try:
            if self.process.poll() is None or not self.output_drained:
                self.interrupted = True
                try: os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            self.process.wait(timeout=2)
        finally:
            self.selector.close()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None: stream.close()


def command(argv, name, state, seconds=15):
    child = Child(argv, state)
    try:
        code = child.finish(seconds)
        if code != 0: raise GateFailure('command_exit')
        raw = bytes(child.data['stdout'])
    finally:
        try: child.stop()
        except (OSError, subprocess.SubprocessError): state.cleanup_ok = False
        state.report['commands'][name] = child.facts()
        state.report['cleanup'] = 'reaped' if state.cleanup_ok else 'unverified'
    if not state.cleanup_ok: raise GateFailure('cleanup_unverified')
    return raw


def write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(raw)


def helper_source(spec):
    require(type(spec) is ProbeSpec)
    return ('''#include "provider.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
static int command(char *value) {
    ssize_t count;
    do { count = read(STDIN_FILENO, value, 1); } while (count < 0 && errno == EINTR);
    return count == 1;
}
__attribute__((noinline,used,visibility("default"))) void ''' + spec.function + '''(void) {
    ''' + spec.provider.upper() + '_OBSERVE(0x' + spec.argument + '''ULL);
}
int main(void) {
    char value;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("HELPER_READY %ld\\n", (long)getpid());
    if (!command(&value) || value != 'O') return 2;
    ''' + spec.function + '''();
    puts("HELPER_RETURNED");
    if (!command(&value) || value != 'Q') return 3;
    return 0;
}
''').encode()


def build(directory, spec, architecture, state):
    require(type(spec) is ProbeSpec and architecture in ('arm64', 'x86_64'))
    provider_source = ('provider ' + spec.provider + ' { probe observe(unsigned long long); };\n').encode()
    source = helper_source(spec)
    write_private(directory / 'provider.d', provider_source)
    write_private(directory / 'helper.c', source)
    state.report['hashes'].update(provider_source=digest(provider_source), helper_source=digest(source))
    state.stage('header')
    command(['/usr/sbin/dtrace', '-h', '-s', str(directory / 'provider.d'), '-o', str(directory / 'provider.h')], 'header', state)
    require((directory / 'provider.h').stat().st_size <= 65536)
    header = (directory / 'provider.h').read_bytes()
    validate_header(header, spec.provider)
    state.report['hashes']['header'] = digest(header)
    state.stage('compile')
    command(['/usr/bin/xcrun', 'clang', '-arch', architecture, '-O0', '-g', '-Wall', '-Wextra', '-Werror', '-I', str(directory),
             str(directory / 'helper.c'), '-o', str(directory / 'helper')], 'compile', state, 30)
    os.chmod(directory / 'helper', 0o700)
    state.stage('sign')
    command(['/usr/bin/codesign', '-s', '-', '-f', str(directory / 'helper')], 'sign', state)
    state.stage('verify')
    command(['/usr/bin/codesign', '--verify', '--strict', str(directory / 'helper')], 'verify', state)
    require((directory / 'helper').stat().st_size <= 4 * 1024 * 1024)
    state.report['hashes']['helper_binary'] = digest((directory / 'helper').read_bytes())


def validate_final_output(tracer, helper, ready, hit):
    require(tracer == b'TRACER_READY\n' + hit + b'\n' and helper == ready + b'HELPER_RETURNED\n')


def execute(directory, spec, state, *, run_command=command):
    helper = tracer = None
    try:
        state.stage('helper_ready')
        helper = Child([str(directory / 'helper')], state, stdin=True)
        state.report['helper_pid'] = helper.process.pid
        ready = helper.line(10)
        parse_ready(ready, helper.process.pid)
        probe = spec.bind(helper.process.pid)
        state.stage('listing')
        listing = run_command(['/usr/sbin/dtrace', '-l', '-n', spec.provider + '*:::observe'], 'listing', state, 20)
        state.report['listing_rows'] = parse_listing(listing, probe)
        state.stage('compile_panic')
        compile_argv = panic_compile_command(probe)
        state.report['hashes']['panic_program'] = digest(compile_argv[-1].encode())
        run_command(compile_argv, 'panic_compile', state, 20)
        require(state.cleanup_ok and helper.process.poll() is None)
        state.stage('tracer_ready')
        argv = tracer_command(probe)
        state.report['hashes']['tracer_program'] = digest(argv[-1].encode())
        tracer = Child(argv, state)
        state.report['tracer_pid'] = tracer.process.pid
        require(tracer.line(10) == b'TRACER_READY\n')
        require(helper.process.poll() is None and tracer.process.poll() is None)
        state.stage('once')
        state.report['o_attempts'] = 1
        require(os.write(helper.process.stdin.fileno(), b'O') == 1)
        state.report['o_written'] = True
        state.stage('hit')
        hit = tracer.line(10)
        parse_hit(hit, probe)
        state.report['hit_count'] = 1
        state.stage('returned')
        require(helper.line(5) == b'HELPER_RETURNED\n')
        state.report['helper_returned'] = True
        state.stage('quit')
        require(os.write(helper.process.stdin.fileno(), b'Q') == 1)
        state.report['q_written'] = True
        state.stage('exits')
        require(tracer.finish(5) == helper.finish(5) == 0)
        validate_final_output(bytes(tracer.data['stdout']), bytes(helper.data['stdout']), ready, hit)
    finally:
        for name, child in (('tracer', tracer), ('helper', helper)):
            if child is not None:
                try: child.stop()
                except (OSError, subprocess.SubprocessError): state.cleanup_ok = False
                state.report['commands'][name] = child.facts()
        state.report['cleanup'] = 'reaped' if state.cleanup_ok else 'unverified'


def finalize_report(report):
    if report['status'] == 'passed' and report['cleanup'] != 'reaped':
        report = {**report, 'status': 'failed', 'stage': 'exits', 'reason': 'cleanup_unverified'}
    return public_report(report)


def deadline_signal(_signum, _frame): raise GateFailure('deadline')


def interrupted_signal(_signum, _frame): raise GateFailure('interrupted')


def install_signal_handlers():
    return {signal.SIGALRM: signal.signal(signal.SIGALRM, deadline_signal),
            signal.SIGTERM: signal.signal(signal.SIGTERM, interrupted_signal),
            signal.SIGINT: signal.signal(signal.SIGINT, interrupted_signal)}


def restore_signal_handlers(previous):
    for number, handler in previous.items(): signal.signal(number, handler)


def main():
    os.environ.pop('GITHUB_TOKEN', None)
    os.environ.pop('GH_TOKEN', None)
    state = State()
    previous = install_signal_handlers()
    signal.setitimer(signal.ITIMER_REAL, 180)
    try:
        require(len(sys.argv) == 1)
        state.report['context'] = checked_context(os.environ)
        system, machine = os.uname().sysname, os.uname().machine
        state.report.update(system=system if system == 'Darwin' else 'other', machine=machine if machine in ('arm64', 'x86_64') else 'other', root=os.geteuid() == 0)
        require(system == 'Darwin' and machine == 'x86_64')
        if os.geteuid() != 0: raise GateFailure('requires_root')
        runner_temp = Path(os.environ['RUNNER_TEMP'])
        require(runner_temp.is_dir())
        state.stage('sources')
        state.report['hashes'].update(script=digest(Path(__file__).read_bytes()), workflow=digest((Path(__file__).resolve().parents[1] / '.github/workflows/usdt-feasibility.yml').read_bytes()))
        state.stage('kernel')
        live = command(['/usr/sbin/sysctl', '-n', 'kern.uuid'], 'kernel_uuid', state).decode('ascii').strip().upper()
        file = command(['/usr/bin/xcrun', 'dwarfdump', '--uuid', '/System/Library/Kernels/kernel'], 'kernel_file', state, 20).decode('ascii')
        require(live == KERNEL_UUID and re.findall(r'UUID:\s*([0-9A-Fa-f-]+)\s*\(x86_64\)', file) == [KERNEL_UUID])
        state.report['kernel_matched'] = True
        nonce = secrets.token_hex(32)
        spec = ProbeSpec(nonce)
        state.report['hashes'].update(nonce=digest(nonce.encode()), provider=digest(spec.provider.encode()), argument=digest(spec.argument.encode()))
        with tempfile.TemporaryDirectory(prefix='usdt-feasibility-', dir=runner_temp) as work:
            directory = Path(work)
            require(directory.stat().st_mode & 0o777 == 0o700 and directory.stat().st_uid == os.geteuid())
            build(directory, spec, machine, state)
            execute(directory, spec, state)
        state.stage('completed')
        state.report['status'] = 'passed'
    except GateFailure as error: state.report.update(status='failed', reason=error.reason)
    except (OSError, subprocess.SubprocessError): state.report['reason'] = 'os_error'
    except (ValueError, TypeError, KeyError, UnicodeError): state.report['reason'] = 'invalid'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        restore_signal_handlers(previous)
    public = finalize_report(state.report)
    target = Path(os.environ['RUNNER_TEMP']) / 'debug'
    target.mkdir(mode=0o755, exist_ok=True)
    require(not target.is_symlink())
    fd = os.open(target / 'usdt-feasibility.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(json.dumps(public, sort_keys=True) + '\n')
    print(json.dumps(public, sort_keys=True), flush=True)
    return 0 if public['status'] == 'passed' else 1


if __name__ == '__main__': sys.exit(main())
