"""Bounded userspace UDP connection-state comparison on one owned socket pair."""
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import socket
import sys
import time

import kdp_udp_preflight as u
import recovery_netdump as n

PROTOCOL = 'udp-connection-control-v1'
MODES = ('unconnected', 'connected', 'unconnected')
SOURCE_KEYS = n.NETWORK_KEYS + ('control_sha256', 'workflow_sha256')
CATEGORIES = ('length_invalid', 'magic_invalid', 'nonce_mismatch', 'kind_invalid', 'sequence_invalid',
              'valid_nonce_other_ip', 'valid_nonce_same_ip_other_port', 'exact_peer')
require, exact = n.require, n.exact


def sources():
    paths = (n.__file__, u.__file__, u.wire.__file__, u.reports.__file__, __file__,
             Path(__file__).resolve().parents[1] / '.github/workflows/udp-connection-control.yml')
    return {key: hashlib.sha256(Path(path).read_bytes()).hexdigest() for key, path in zip(SOURCE_KEYS, paths)}


def make_base(ctx, pins, endpoint, local_port, nonce):
    value = {'protocol': PROTOCOL, 'scope': 'userspace_non_kernel', 'binding': n.context_binding(ctx), 'role': ctx['role'], 'sources': pins,
             'endpoint': endpoint, 'local_port': local_port, 'nonce': nonce,
             'context': {'repository': 'Code-Hex/vz-ci-test', 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
                         'runner_environment': 'github-hosted', 'kernel_uuid': u.UUID if ctx['role'] == 'intel' else None}}
    return validate_base(value)


def validate_base(value):
    exact(value, ('protocol', 'scope', 'binding', 'role', 'sources', 'endpoint', 'local_port', 'nonce', 'context'))
    require(value['protocol'] == PROTOCOL and value['scope'] == 'userspace_non_kernel' and value['role'] in ('intel', 'receiver'))
    require(type(value['binding']) is str)
    run, attempt, sha = value['binding'].split('/')
    n.context_binding({'run': run, 'attempt': attempt, 'sha': sha, 'role': value['role'], 'port_mode': 'kernel-source'})
    exact(value['sources'], SOURCE_KEYS)
    require(all(n.hexadecimal(item) for item in value['sources'].values()) and n.hexadecimal(value['nonce']))
    endpoint = n.Endpoint.from_record(value['endpoint'])
    require(type(value['local_port']) is int and 1 <= value['local_port'] <= 65535 and
            (value['role'] != 'receiver' or endpoint.port != 41139))
    require(value['context'] == {'repository': 'Code-Hex/vz-ci-test', 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
                                'runner_environment': 'github-hosted', 'kernel_uuid': u.UUID if value['role'] == 'intel' else None})
    return json.loads(n.canonical(value))


def pair_bases(a, b):
    a, b = validate_base(a), validate_base(b)
    require(a['role'] != b['role'] and a['binding'] == b['binding'] and a['sources'] == b['sources'] and a['nonce'] != b['nonce'])
    host, receiver = (a, b) if a['role'] == 'intel' else (b, a)
    require(host['local_port'] == receiver['endpoint']['port'] and host['endpoint'] != receiver['endpoint'])
    return host, receiver


def round_scope(a, b, index):
    require(type(index) is int and 0 <= index < 3)
    host, receiver = pair_bases(a, b)
    return {'domain': PROTOCOL, 'intel': host, 'receiver': receiver, 'index': index, 'mode': MODES[index]}


def packet_nonce(scope, role):
    require(role in ('intel', 'receiver'))
    return bytes.fromhex(n.digest({'scope': scope, 'role': role})[:32])


def empty_counts(): return {'total': 0, 'received_bytes': 0, **{key: 0 for key in CATEGORIES}}


def validate_counts(value):
    exact(value, ('total', 'received_bytes') + CATEGORIES)
    require(all(type(item) is int and item >= 0 for item in value.values()) and value['total'] <= 4096 and
            value['received_bytes'] <= value['total'] * 1024 and sum(value[key] for key in CATEGORIES) == value['total'])
    return dict(value)


class Observer:
    """Count recvfrom results after socket filtering, without changing acceptance."""
    def __init__(self, sock, peer, own_nonce, peer_nonce, *, connected):
        require(type(connected) is bool and len(own_nonce) == len(peer_nonce) == 16 and own_nonce != peer_nonce)
        self.sock, self.peer, self.own_nonce, self.peer_nonce = sock, peer, own_nonce, peer_nonce
        self.connected, self.counts, self.sent_sequences = connected, empty_counts(), set()

    def fileno(self): return self.sock.fileno()

    def sendto(self, packet, address):
        require(address == self.peer)
        sent = self.sock.send(packet) if self.connected else self.sock.sendto(packet, address)
        if sent == len(packet) and len(packet) == u.PACKET.size:
            magic, kind, sender, receiver, sequence = u.PACKET.unpack(packet)
            if magic == b'KDP1' and kind == 1 and sender == self.own_nonce and receiver == self.peer_nonce and sequence != 0:
                require(len(self.sent_sequences) < 280 or sequence in self.sent_sequences)
                self.sent_sequences.add(sequence)
        return sent

    def recvfrom(self, size):
        require(self.counts['total'] < 4096 and 0 < size <= 1024)
        packet, address = self.sock.recvfrom(size)
        self.counts['total'] += 1
        self.counts['received_bytes'] += len(packet)
        if len(packet) != u.PACKET.size: category = 'length_invalid'
        else:
            magic, kind, sender, receiver, sequence = u.PACKET.unpack(packet)
            if magic != b'KDP1': category = 'magic_invalid'
            elif sender != self.peer_nonce or receiver != self.own_nonce: category = 'nonce_mismatch'
            elif kind not in (1, 2): category = 'kind_invalid'
            elif sequence == 0 or (kind == 2 and sequence not in self.sent_sequences): category = 'sequence_invalid'
            elif address[0] != self.peer[0]: category = 'valid_nonce_other_ip'
            elif address != self.peer: category = 'valid_nonce_same_ip_other_port'
            else: category = 'exact_peer'
        self.counts[category] += 1
        return packet, address

    def fact(self): return validate_counts(self.counts)


def disconnect_owned_udp(sock):
    require(sys.platform == 'darwin' and type(sock) is socket.socket and sock.family == socket.AF_INET and sock.type == socket.SOCK_DGRAM)
    fd, port = sock.fileno(), sock.getsockname()[1]
    require(fd >= 0 and sock.getpeername())
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    function = library.disconnectx
    function.argtypes, function.restype = (ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32), ctypes.c_int
    require(function(fd, 0, 0) == 0)
    require(sock.fileno() == fd and sock.getsockname()[1] == port)
    assert_unconnected(sock)


def assert_unconnected(sock):
    try: sock.getpeername()
    except OSError as error:
        require(error.errno == errno.ENOTCONN)
    else: raise ValueError('control_connected')


def not_started():
    return {'status': 'not_started_peer_done', 'overlap': 'overlap_unverified', 'adapter_connected': None,
            'exchange': None, 'counters': None, 'timing': None}


def validate_result(value, role, index):
    require(role in ('intel', 'receiver') and type(index) is int and 0 <= index < 3)
    exact(value, ('status', 'overlap', 'adapter_connected', 'exchange', 'counters', 'timing'))
    if value['status'] == 'not_started_peer_done': require(value == not_started())
    else:
        require(value['status'] == 'observed' and type(value['adapter_connected']) is bool and
                value['adapter_connected'] == (role == 'intel' and MODES[index] == 'connected'))
        stats = value['exchange']
        exact(stats, ('hello_received', 'ack_received', 'sent', 'valid_peer_port_mismatches', 'other_peer_port_count'))
        require(type(stats['hello_received']) is bool and type(stats['ack_received']) is bool and type(stats['sent']) is int and
                0 <= stats['sent'] <= 280 and type(stats['valid_peer_port_mismatches']) is int and
                0 <= stats['valid_peer_port_mismatches'] < 2 ** 31 and type(stats['other_peer_port_count']) is int and
                0 <= stats['other_peer_port_count'] <= 8)
        positive = stats['hello_received'] and stats['ack_received'] and stats['valid_peer_port_mismatches'] == 0
        require(value['overlap'] == ('matching_packets_observed' if positive else 'overlap_unverified'))
        timing = value['timing']
        exact(timing, ('monotonic_start', 'monotonic_end', 'unix_start', 'unix_end'))
        require(all(type(item) in (int, float) and 0 < item < 2 ** 53 and math.isfinite(item) for item in timing.values()) and
                0 <= timing['monotonic_end'] - timing['monotonic_start'] <= 360)
        counts = validate_counts(value['counters'])
        require(stats['valid_peer_port_mismatches'] == counts['valid_nonce_same_ip_other_port'] and
                stats['other_peer_port_count'] <= stats['valid_peer_port_mismatches'] and
                (stats['other_peer_port_count'] == 0) == (stats['valid_peer_port_mismatches'] == 0) and
                (not (stats['hello_received'] or stats['ack_received']) or counts['exact_peer'] > 0))
    return json.loads(n.canonical(value))


def validate_record(value):
    exact(value, ('base', 'peer', 'phase', 'history', 'failure'))
    base = validate_base(value['base'])
    require(value['phase'] in ('offer', 'ready', 'done', 'complete', 'failed') and type(value['history']) is list and len(value['history']) <= 3)
    peer = value['peer']
    if peer is not None:
        exact(peer, ('check_id', 'base'))
        require(type(peer['check_id']) is int and peer['check_id'] > 0)
        pair_bases(base, peer['base'])
    for index, item in enumerate(value['history']):
        exact(item, ('index', 'mode', 'scope_sha256', 'result'))
        require(peer is not None and type(item['index']) is int and item['index'] == index and item['mode'] == MODES[index] and
                item['scope_sha256'] == n.digest(round_scope(base, peer['base'], index)))
        if item['result'] is not None: validate_result(item['result'], base['role'], index)
        if index < len(value['history']) - 1: require(item['result'] is not None)
    history = value['history']
    if value['phase'] == 'offer': require(not history)
    elif value['phase'] == 'ready': require(history and history[-1]['result'] is None)
    elif value['phase'] == 'done': require(history and history[-1]['result'] is not None)
    elif value['phase'] == 'complete': require(len(history) == 3 and all(item['result'] is not None for item in history))
    if value['phase'] == 'failed':
        exact(value['failure'], ('kind', 'evidence'))
        require(value['failure']['kind'] == 'control_failed')
        if value['failure']['evidence'] is not None: n.validate_evidence(value['failure']['evidence'])
    else: require(value['failure'] is None)
    return json.loads(n.canonical(value))


def validate_transition(previous, current):
    previous, current = validate_record(previous), validate_record(current)
    require(previous['base'] == current['base'] and (previous['peer'] is None or previous['peer'] == current['peer']))
    a, b = previous['history'], current['history']
    require(len(a) <= len(b) <= len(a) + 1)
    for old, new in zip(a, b):
        require({key: old[key] for key in ('index', 'mode', 'scope_sha256')} == {key: new[key] for key in ('index', 'mode', 'scope_sha256')})
        if old['result'] is not None: require(old['result'] == new['result'])
    if len(b) > len(a): require(all(item['result'] is not None for item in b[:len(a)]))
    if previous['phase'] in ('complete', 'failed'): require(previous == current)
    return current


def ready_record(record, index):
    record = validate_record(record)
    require(type(index) is int and index == len(record['history']) and record['peer'] is not None and
            all(item['result'] is not None for item in record['history']))
    value = {**record, 'phase': 'ready', 'history': record['history'] + [{'index': index, 'mode': MODES[index],
             'scope_sha256': n.digest(round_scope(record['base'], record['peer']['base'], index)), 'result': None}]}
    return validate_transition(record, value)


def done_record(record, result):
    record = validate_record(record)
    require(record['phase'] == 'ready')
    value = {**record, 'phase': 'done', 'history': record['history'][:-1] + [{**record['history'][-1], 'result': result}]}
    return validate_transition(record, value)


def start_decision(peer, index):
    peer = validate_record(peer)
    require(peer['phase'] != 'failed')
    if len(peer['history']) <= index: return None
    if peer['history'][index]['result'] is not None: return 'not_started_peer_done'
    require(peer['phase'] == 'ready' and len(peer['history']) == index + 1)
    return 'run'


def attributes(ctx, role):
    return 'UDP connection control ' + role + ' ' + ctx['run'], 'udp-connection-control/' + n.context_binding(ctx) + '/' + role


def verify_check(check, ctx, role, stage, *, expected_id=None, expected_summary=None):
    require(stage in ('post_identity', 'get_readback'))
    name, external = attributes(ctx, role)
    item = check if type(check) is dict else {}
    number = item.get('id')
    app = item.get('app') if type(item.get('app')) is dict else {}
    matches = {'id': type(number) is int and number > 0 and (expected_id is None or number == expected_id),
               'name': item.get('name') == name, 'head_sha': item.get('head_sha') == ctx['sha'],
               'external_id': item.get('external_id') == external, 'app_id': app.get('id') == 15368,
               'app_slug': app.get('slug') == 'github-actions',
               'details_url': item.get('details_url') == 'https://github.com/Code-Hex/vz-ci-test/runs/' + str(number)}
    if stage == 'get_readback':
        output = item.get('output')
        summary = output.get('summary') if type(output) is dict else None
        matches.update(status=item.get('status') == 'completed', conclusion=item.get('conclusion') == 'neutral',
                       summary=type(summary) is str and len(summary.encode()) <= 16000 and
                               (expected_summary is None or summary == expected_summary),
                       title=type(output) is dict and output.get('title') == 'Userspace UDP connection control',
                       text=type(output) is dict and output.get('text') in (None, ''))
    if not all(matches.values()):
        raise n.EvidenceFailure({'kind': 'check_mismatch', 'stage': stage, 'matches': matches})
    return number


def check_identity(check, ctx, role, expected_id=None):
    return verify_check(check, ctx, role, 'post_identity', expected_id=expected_id)


def read_check(ctx, token, role, deadline, expected_id=None, expected_record=None):
    if expected_id is None:
        listing = n.call(deadline, 'GET', '/commits/' + ctx['sha'] + '/check-runs?filter=all&per_page=100', token)
        require(type(listing) is dict and type(listing.get('total_count')) is int and type(listing.get('check_runs')) is list and
                listing['total_count'] == len(listing['check_runs']) <= 100 and all(type(item) is dict for item in listing['check_runs']))
        name, external = attributes(ctx, role)
        matches = [item for item in listing['check_runs'] if item.get('name') == name or item.get('external_id') == external]
        require(len(matches) <= 1)
        if not matches: return None
        expected_id = matches[0].get('id')
        require(type(expected_id) is int and expected_id > 0)
    check = n.call(deadline, 'GET', '/check-runs/' + str(expected_id), token)
    expected_summary = n.canonical(expected_record) if expected_record is not None else None
    verify_check(check, ctx, role, 'get_readback', expected_id=expected_id, expected_summary=expected_summary)
    output = check['output']
    value = json.loads(output['summary'])
    if n.canonical(value) != output['summary']:
        verify_check(check, ctx, role, 'get_readback', expected_id=expected_id, expected_summary=n.canonical(value))
    return expected_id, validate_record(value)


class Owner:
    def __init__(self, ctx, token, hard):
        self.ctx, self.token, self.hard = ctx, token, hard
        self.check_id, self.attempted, self.latest = None, False, None

    def publish(self, record, deadline):
        record = validate_record(record)
        if self.latest is not None: validate_transition(self.latest, record)
        self.latest = record
        summary = n.canonical(record)
        require(len(summary.encode()) <= 16000)
        payload = {'status': 'completed', 'conclusion': 'neutral',
                   'output': {'title': 'Userspace UDP connection control', 'summary': summary, 'text': ''}}
        if self.check_id is None:
            require(not self.attempted)
            name, external = attributes(self.ctx, self.ctx['role'])
            self.attempted = True
            created = n.call(deadline, 'POST', '/check-runs', self.token, {**payload, 'name': name, 'external_id': external, 'head_sha': self.ctx['sha']})
            self.check_id = check_identity(created, self.ctx, self.ctx['role'])
        else: n.call(deadline, 'PATCH', '/check-runs/' + str(self.check_id), self.token, payload)
        read_check(self.ctx, self.token, self.ctx['role'], deadline, self.check_id, expected_record=record)

    def cleanup(self, evidence):
        if self.check_id is None: return 'not_acknowledged' if self.attempted else 'not_created'
        try:
            self.publish({**self.latest, 'phase': 'failed', 'failure': {'kind': 'control_failed', 'evidence': evidence}}, self.hard)
            return 'acknowledged'
        except Exception: return 'not_acknowledged'


class Peer:
    def __init__(self, ctx, token, role, pins):
        self.ctx, self.token, self.role, self.pins = ctx, token, role, pins
        self.check_id, self.latest, self.expected_peer = None, None, None

    def read(self, deadline):
        found = read_check(self.ctx, self.token, self.role, deadline, self.check_id)
        if found is None: return None
        number, record = found
        base = record['base']
        require(base['role'] == self.role and base['binding'] == n.context_binding(self.ctx) and base['sources'] == self.pins)
        if self.latest is not None: validate_transition(self.latest, record)
        if self.expected_peer is not None and record['peer'] is not None: require(record['peer'] == self.expected_peer)
        self.check_id, self.latest = number, record
        require(record['phase'] != 'failed')
        return record

    def wait(self, predicate, deadline):
        while True:
            record = self.read(deadline)
            if record is not None and predicate(record): return record
            time.sleep(2)


def run_round(sock, peer, scope, role, connected):
    own_nonce, peer_nonce = packet_nonce(scope, role), packet_nonce(scope, 'receiver' if role == 'intel' else 'intel')
    observer = Observer(sock, peer, own_nonce, peer_nonce, connected=connected)
    monotonic_start, unix_start = time.monotonic(), time.time()
    raw = u.exchange(observer, peer, own_nonce, peer_nonce, 20)
    unix_end, monotonic_end = time.time(), time.monotonic()
    stats = {key: raw[key] for key in ('hello_received', 'ack_received', 'sent', 'valid_peer_port_mismatches')}
    stats['other_peer_port_count'] = len(raw['other_peer_ports'])
    positive = stats['hello_received'] and stats['ack_received'] and stats['valid_peer_port_mismatches'] == 0
    return validate_result({'status': 'observed', 'overlap': 'matching_packets_observed' if positive else 'overlap_unverified',
                            'adapter_connected': connected, 'exchange': stats, 'counters': observer.fact(),
                            'timing': {'monotonic_start': monotonic_start, 'monotonic_end': monotonic_end,
                                       'unix_start': unix_start, 'unix_end': unix_end}}, role, scope['index'])


def control_result(status, cleanup, record, evidence=None):
    return {'status': status, 'cleanup': cleanup, 'record': record, 'evidence': evidence}


def run_control(ctx, token, hard):
    require(ctx['port_mode'] == 'kernel-source')
    deadline, pins = n.operation_deadline(hard, time.monotonic()), sources()
    role, other = ctx['role'], 'receiver' if ctx['role'] == 'intel' else 'intel'
    owner, peer, sock = Owner(ctx, token, hard), Peer(ctx, token, other, pins), None
    require(read_check(ctx, token, role, deadline) is None)
    try:
        offered = peer.wait(lambda value: value['phase'] == 'offer' and not value['history'], deadline) if role == 'intel' else None
        sock, endpoint = n.open_socket(offered['base']['endpoint']['port'] if offered else 0)
        base = make_base(ctx, pins, endpoint.record(), sock.getsockname()[1], secrets.token_hex(32))
        record = {'base': base, 'peer': {'check_id': peer.check_id, 'base': offered['base']} if offered else None,
                  'phase': 'offer', 'history': [], 'failure': None}
        owner.publish(record, deadline)
        peer.expected_peer = {'check_id': owner.check_id, 'base': base}
        if role == 'receiver':
            offered = peer.wait(lambda value: value['peer'] == {'check_id': owner.check_id, 'base': base}, deadline)
            record = {**record, 'peer': {'check_id': peer.check_id, 'base': offered['base']}}
            owner.publish(record, deadline)
        else:
            peer.wait(lambda value: value['peer'] == {'check_id': owner.check_id, 'base': base}, deadline)
        target = (offered['base']['endpoint']['ip'], offered['base']['endpoint']['port'])
        fd, port = sock.fileno(), sock.getsockname()[1]
        for index, mode in enumerate(MODES):
            if role == 'intel' and index == 1: sock.connect(target)
            if role == 'intel' and index == 2: disconnect_owned_udp(sock)
            connected = role == 'intel' and mode == 'connected'
            require(sock.fileno() == fd and sock.getsockname()[1] == port)
            if connected: require(sock.getpeername() == target)
            else: assert_unconnected(sock)
            record = ready_record(record, index)
            owner.publish(record, deadline)
            peer.wait(lambda value: start_decision(value, index) is not None, deadline)
            current = peer.read(deadline)
            decision = start_decision(current, index)
            require(decision is not None and deadline - time.monotonic() >= 20)
            result = not_started() if decision == 'not_started_peer_done' else run_round(sock, target, round_scope(base, offered['base'], index), role, connected)
            require(sock.fileno() == fd and sock.getsockname()[1] == port)
            record = done_record(record, result)
            owner.publish(record, deadline)
            peer.wait(lambda value: len(value['history']) > index and value['history'][index]['result'] is not None, deadline)
        record = {**record, 'phase': 'complete'}
        owner.publish(record, deadline)
        return control_result('completed', 'not_required', record)
    except Exception as error:
        evidence = n.error_evidence(error)
        return control_result('failed', owner.cleanup(evidence), owner.latest, evidence)
    finally:
        if sock is not None: sock.close()


def public_projection(value):
    exact(value, ('status', 'cleanup', 'record', 'evidence'))
    require(value['status'] in ('completed', 'failed') and value['cleanup'] in
            ('not_required', 'not_created', 'not_acknowledged', 'acknowledged'))
    if value['evidence'] is not None: n.validate_evidence(value['evidence'])
    record = validate_record(value['record']) if value['record'] is not None else None
    if value['status'] == 'completed': require(record is not None and record['phase'] == 'complete')
    base = record['base'] if record else None
    peer = record['peer'] if record else None
    return {'scope': 'userspace_non_kernel', 'clock_scope': 'local_unsynchronized', 'status': value['status'],
            'cleanup': value['cleanup'], 'evidence': value['evidence'], 'record_sha256': n.digest(record) if record else None,
            'binding': base['binding'] if base else None, 'role': base['role'] if base else None,
            'sources': base['sources'] if base else None, 'context': base['context'] if base else None,
            'endpoint_sha256': n.digest(base['endpoint']) if base else None,
            'peer_endpoint_sha256': n.digest(peer['base']['endpoint']) if peer else None,
            'peer_check_id': peer['check_id'] if peer else None, 'history': record['history'] if record else [],
            'failure': record['failure'] if record else None}


def main():
    token = os.environ.pop('GITHUB_TOKEN', '')
    value = control_result('failed', 'not_created', None)
    try:
        require(len(sys.argv) == 1 and token)
        with n.bounded_session(360) as hard:
            value = run_control(u.validate_context(), token, hard)
    except Exception as error:
        value['evidence'] = n.error_evidence(error)
    directory = Path(os.environ['RUNNER_TEMP']) / 'debug'
    directory.mkdir(exist_ok=True)
    require(not directory.is_symlink())
    public = public_projection(value)
    n.write_file(directory / 'udp-connection-control.json', public, 0o644)
    print(n.canonical(public), flush=True)
    return 0 if value['status'] == 'completed' else 1


if __name__ == '__main__': sys.exit(main())
