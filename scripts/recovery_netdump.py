"""Actions-only userspace discovery; no boot settings writes or kernel packets."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time

import kdp_udp_preflight as udp
import recovery_reports as reports
import recovery_sources as sources
from recovery_netdump_settings import NetdumpSettings

SCOPE = 'netdump_discovery_only'
NETWORK_KEYS = ('netdump_sha256', 'udp_sha256', 'codec_sha256', 'reports_sha256')


def require(condition):
    if not condition: raise ValueError('discovery_invalid')


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def hexadecimal(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode('ascii')).hexdigest()


def private_ipv4(value):
    require(type(value) is str)
    address = ipaddress.IPv4Address(value)
    require(str(address) == value and not (address.is_unspecified or address.is_loopback or
            address.is_multicast or address.is_reserved or int(address) < 0x01000000))
    return value


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int

    def __post_init__(self):
        require(udp.public_endpoint(self.ip, self.port))
        require(not ipaddress.IPv4Address(self.ip).is_multicast)

    def record(self): return {'ip': self.ip, 'port': self.port}

    @classmethod
    def from_record(cls, value):
        exact(value, ('ip', 'port'))
        return cls(**value)


@dataclass(frozen=True)
class HelloStats:
    hello_received: bool
    ack_received: bool
    sent: int

    def __post_init__(self):
        require(self.hello_received is True and self.ack_received is True and type(self.sent) is int and 1 <= self.sent <= 280)

    def record(self): return {'hello_received': True, 'ack_received': True, 'sent': self.sent}

    @classmethod
    def from_record(cls, value):
        exact(value, ('hello_received', 'ack_received', 'sent'))
        return cls(**value)


@dataclass(frozen=True)
class ReceiverOffer:
    binding: str
    nonce: str
    endpoint: Endpoint
    local_port: int
    cert_fingerprint: str
    core_identity: str
    network_sources: tuple

    def __post_init__(self):
        require(type(self.binding) is str and re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}', self.binding))
        require(hexadecimal(self.nonce, 32) and type(self.endpoint) is Endpoint and self.endpoint.port != 41139)
        require(type(self.local_port) is int and 1 <= self.local_port <= 65535)
        require(hexadecimal(self.cert_fingerprint) and hexadecimal(self.core_identity))
        require(type(self.network_sources) is tuple and len(self.network_sources) == 4)
        require(all(type(pair) is tuple and len(pair) == 2 for pair in self.network_sources))
        require(tuple(key for key, value in self.network_sources) == NETWORK_KEYS and
                all(hexadecimal(value) for key, value in self.network_sources))

    def record(self):
        return {'binding': self.binding, 'nonce': self.nonce, 'endpoint': self.endpoint.record(), 'local_port': self.local_port,
                'cert_fingerprint': self.cert_fingerprint, 'core_identity': self.core_identity, 'network_sources': dict(self.network_sources)}

    def digest(self): return digest(self.record())

    @classmethod
    def from_record(cls, value):
        exact(value, ('binding', 'nonce', 'endpoint', 'local_port', 'cert_fingerprint', 'core_identity', 'network_sources'))
        exact(value['network_sources'], NETWORK_KEYS)
        return cls(value['binding'], value['nonce'], Endpoint.from_record(value['endpoint']), value['local_port'],
                   value['cert_fingerprint'], value['core_identity'], tuple((key, value['network_sources'][key]) for key in NETWORK_KEYS))


@dataclass(frozen=True)
class DiscoveryPlan:
    offer: ReceiverOffer
    nonce: str
    intel_endpoint: Endpoint
    source_ipv4: str
    interface: str
    settings: NetdumpSettings
    stats: HelloStats | None

    def __post_init__(self):
        require(type(self.offer) is ReceiverOffer and hexadecimal(self.nonce) and type(self.intel_endpoint) is Endpoint)
        require(self.nonce[:32] != self.offer.nonce)
        private_ipv4(self.source_ipv4)
        require(type(self.interface) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,15}', self.interface))
        require(type(self.settings) is NetdumpSettings and self.settings.receiver_ipv4 == self.offer.endpoint.ip and
                self.settings.port == self.offer.endpoint.port and self.settings.corename == self.nonce[:16])
        require(self.stats is None or type(self.stats) is HelloStats)

    def record(self):
        return {'offer': self.offer.record(), 'nonce': self.nonce, 'intel_endpoint': self.intel_endpoint.record(),
                'source_ipv4': self.source_ipv4, 'interface': self.interface, 'settings': self.settings.record(),
                'stats': self.stats.record() if self.stats else None}

    @classmethod
    def from_record(cls, value):
        exact(value, ('offer', 'nonce', 'intel_endpoint', 'source_ipv4', 'interface', 'settings', 'stats'))
        return cls(ReceiverOffer.from_record(value['offer']), value['nonce'], Endpoint.from_record(value['intel_endpoint']),
                   value['source_ipv4'], value['interface'], NetdumpSettings.from_record(value['settings']),
                   HelloStats.from_record(value['stats']) if value['stats'] is not None else None)

    def public_fact(self):
        result = {'scope': SCOPE, 'phase': 'plan' if self.stats else 'probe_ready', 'binding': self.offer.binding,
                  'nonce': self.nonce, 'receiver_offer_digest': self.offer.digest(), 'receiver_nonce': self.offer.nonce,
                  'intel_public_endpoint': self.intel_endpoint.record(), 'local_port': self.settings.port,
                  'receiver_endpoint': self.offer.endpoint.record(), 'settings_sha256': self.settings.digest(),
                  'sourceIP_sha256': hashlib.sha256(self.source_ipv4.encode('ascii')).hexdigest(),
                  'gateway_sha256': hashlib.sha256(self.settings.router_ipv4.encode('ascii')).hexdigest(),
                  'cert_fingerprint': self.offer.cert_fingerprint, 'core_identity': self.offer.core_identity,
                  'network_sources': dict(self.offer.network_sources)}
        if self.stats: result['stats'] = self.stats.record()
        return result


def context_binding(ctx):
    exact(ctx, ('run', 'attempt', 'sha', 'role', 'port_mode'))
    require(all(type(ctx[key]) is str for key in ctx))
    require(ctx['role'] in ('intel', 'receiver') and ctx['port_mode'] == 'kernel-source')
    binding = '/'.join((ctx['run'], ctx['attempt'], ctx['sha']))
    require(re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}', binding))
    return binding


def match_offer(value, ctx, fingerprint, core, network):
    offer = ReceiverOffer.from_record(value)
    require(offer.binding == context_binding(ctx) and offer.cert_fingerprint == fingerprint and
            offer.core_identity == core and dict(offer.network_sources) == network)
    return offer


def validate_host_fact(value, offer, expected_nonce=None):
    keys = ('scope', 'phase', 'binding', 'nonce', 'receiver_offer_digest', 'receiver_nonce', 'intel_public_endpoint',
            'local_port', 'receiver_endpoint', 'settings_sha256', 'sourceIP_sha256', 'gateway_sha256',
            'cert_fingerprint', 'core_identity', 'network_sources')
    require(type(value) is dict and value.get('phase') in ('probe_ready', 'plan'))
    exact(value, keys + (('stats',) if value['phase'] == 'plan' else ()))
    require(value['scope'] == SCOPE and value['binding'] == offer.binding and hexadecimal(value['nonce']) and
            value['nonce'][:32] != offer.nonce and (expected_nonce is None or value['nonce'] == expected_nonce))
    require(value['receiver_offer_digest'] == offer.digest() and value['receiver_nonce'] == offer.nonce and
            Endpoint.from_record(value['receiver_endpoint']) == offer.endpoint and type(value['local_port']) is int and value['local_port'] == offer.endpoint.port)
    Endpoint.from_record(value['intel_public_endpoint'])
    require(value['cert_fingerprint'] == offer.cert_fingerprint and value['core_identity'] == offer.core_identity and
            value['network_sources'] == dict(offer.network_sources))
    require(all(hexadecimal(value[key]) for key in ('settings_sha256', 'sourceIP_sha256', 'gateway_sha256')))
    if value['phase'] == 'plan': HelloStats.from_record(value['stats'])
    return json.loads(canonical(value))


def plan_base(value): return {key: item for key, item in value.items() if key not in ('phase', 'stats')}


def ack_fact(offer, plan, stats):
    require(validate_host_fact(plan, offer)['phase'] == 'plan' and type(stats) is HelloStats)
    return {'scope': SCOPE, 'phase': 'plan_ack', 'offer': offer.record(), 'offer_digest': offer.digest(),
            'plan': plan, 'stats': stats.record()}


def validate_ack(value, offer, plan):
    exact(value, ('scope', 'phase', 'offer', 'offer_digest', 'plan', 'stats'))
    require(value['scope'] == SCOPE and value['phase'] == 'plan_ack' and ReceiverOffer.from_record(value['offer']) == offer and
            value['offer_digest'] == offer.digest() and validate_host_fact(value['plan'], offer) == plan and plan['phase'] == 'plan')
    HelloStats.from_record(value['stats'])
    return json.loads(canonical(value))


def parse_route(raw):
    require(type(raw) is bytes and len(raw) <= 8192)
    text = raw.decode('ascii')
    fields = {key: [line for line in text.splitlines() if re.match(r'^[ \t]*' + key + r'[ \t]*:', line)]
              for key in ('gateway', 'interface')}
    require(all(len(lines) == 1 for lines in fields.values()))
    values = {key: re.fullmatch(r'[ \t]*' + key + r':[ \t]*(\S+)[ \t]*', lines[0]) for key, lines in fields.items()}
    require(all(values.values()))
    gateway, interface = values['gateway'].group(1), values['interface'].group(1)
    private_ipv4(gateway)
    require(re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,15}', interface))
    return gateway, interface


def check_identity(check, ctx, role):
    number = check.get('id')
    return (type(number) is int and number > 0 and check.get('name') == 'Netdump ' + ('plan' if role == 'intel' else 'receiver') + ' ' + ctx['run']
            and check.get('head_sha') == ctx['sha'] and check.get('external_id') == 'netdump/' + role + '/' + context_binding(ctx)
            and type(check.get('app')) is dict and check['app'].get('id') == 15368 and check['app'].get('slug') == 'github-actions'
            and check.get('details_url') == 'https://github.com/Code-Hex/vz-ci-test/runs/' + str(number))


def select_check(listing, ctx, role):
    require(type(listing) is dict and type(listing.get('check_runs')) is list and type(listing.get('total_count')) is int)
    checks = listing['check_runs']
    require(len(checks) <= 100 and listing['total_count'] == len(checks) and all(type(item) is dict for item in checks))
    name = 'Netdump ' + ('plan' if role == 'intel' else 'receiver') + ' ' + ctx['run']
    external = 'netdump/' + role + '/' + context_binding(ctx)
    matches = [item for item in checks if item.get('name') == name or item.get('external_id') == external]
    require(len(matches) <= 1)
    if not matches: return None
    require(check_identity(matches[0], ctx, role))
    return matches[0]


@contextmanager
def bounded_session():
    started = time.monotonic()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    seconds = min(180, previous_timer[0]) if previous_timer[0] else 180
    def expired(signum, frame): raise TimeoutError('discovery_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield started + seconds
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(.001, previous_timer[0] - (time.monotonic() - started)), previous_timer[1])


def call(deadline, method, path, token, payload=None):
    if deadline - time.monotonic() < 8: raise TimeoutError('discovery_deadline')
    return udp.api(method, path, token, payload)


def check_payload(check, ctx, role):
    require(check_identity(check, ctx, role))
    summary = check.get('output', {}).get('summary')
    require(type(summary) is str and len(summary) <= 16000)
    value = json.loads(summary)
    require(type(value) is dict and canonical(value) == summary)
    phase, status, conclusion = value.get('phase'), check.get('status'), check.get('conclusion')
    if phase in ('offer', 'probe_ready'):
        require(status == 'in_progress' and conclusion is None)
    elif phase == 'plan_ack':
        require(role == 'receiver' and status == 'completed' and conclusion == 'success')
    else:
        require(role == 'intel' and phase == 'plan' and ((status == 'in_progress' and conclusion is None) or
                (status == 'completed' and conclusion == 'success')))
    return value


def peer(ctx, token, role, deadline):
    listed = call(deadline, 'GET', '/commits/' + ctx['sha'] + '/check-runs?filter=all&per_page=100', token)
    selected = select_check(listed, ctx, role)
    if selected is None: return None
    check = call(deadline, 'GET', '/check-runs/' + str(selected['id']), token)
    require(check.get('id') == selected['id'])
    value = check_payload(check, ctx, role)
    return check['id'], value


class DiscoveryFailure(ValueError):
    def __init__(self, cleanup):
        super().__init__('discovery_failed')
        self.cleanup = cleanup


def operation_deadline(hard_deadline, now):
    if hard_deadline - now <= 24: raise TimeoutError('discovery_deadline')
    return hard_deadline - 24


class CheckOwner:
    def __init__(self, ctx, token, role, hard_deadline):
        self.ctx, self.token, self.role, self.hard_deadline = ctx, token, role, hard_deadline
        self.check_id, self.attempted, self.latest = None, False, {'scope': SCOPE}

    def publish(self, value, deadline, *, complete=False):
        self.latest = value
        summary = canonical(value)
        require(len(summary) <= 16000)
        payload = {'status': 'completed' if complete else 'in_progress',
                   'output': {'title': 'Netdump discovery only', 'summary': summary, 'text': ''}}
        if complete: payload['conclusion'] = 'success' if value.get('phase') in ('plan', 'plan_ack') else 'neutral'
        if self.check_id is None:
            require(not self.attempted)
            payload.update(name='Netdump ' + ('plan' if self.role == 'intel' else 'receiver') + ' ' + self.ctx['run'],
                           head_sha=self.ctx['sha'], external_id='netdump/' + self.role + '/' + context_binding(self.ctx))
            self.attempted = True
            created = call(deadline, 'POST', '/check-runs', self.token, payload)
            require(check_identity(created, self.ctx, self.role))
            self.check_id = created['id']
        else:
            call(deadline, 'PATCH', '/check-runs/' + str(self.check_id), self.token, payload)
        saved = call(deadline, 'GET', '/check-runs/' + str(self.check_id), self.token)
        require(check_identity(saved, self.ctx, self.role) and saved['id'] == self.check_id and
                saved.get('status') == payload['status'] and saved.get('conclusion') == payload.get('conclusion') and
                saved.get('output', {}).get('summary') == summary and saved.get('output', {}).get('title') == payload['output']['title'] and
                saved.get('output', {}).get('text') in (None, ''))

    def cleanup(self):
        if self.check_id is None: return 'not_acknowledged' if self.attempted else 'not_created'
        try:
            self.publish({**self.latest, 'phase': 'failed'}, self.hard_deadline, complete=True)
            return 'acknowledged'
        except Exception:
            return 'not_acknowledged'


def wait_peer(ctx, token, role, phases, deadline, check_id=None):
    while time.monotonic() < deadline:
        result = peer(ctx, token, role, deadline)
        if result:
            number, value = result
            require(check_id is None or number == check_id)
            require(value.get('phase') in (('probe_ready', 'plan') if role == 'intel' else ('offer', 'plan_ack')))
            if value['phase'] in phases: return number, value
        time.sleep(.5)
    raise TimeoutError('discovery_deadline')


def source_identity(main_path):
    network = tuple((key, hashlib.sha256(Path(path).read_bytes()).hexdigest()) for key, path in zip(NETWORK_KEYS,
                    (__file__, udp.__file__, udp.wire.__file__, reports.__file__)))
    return sources.identity(main_path), network


def open_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', port))
        candidates = socket.getaddrinfo('stun.cloudflare.com', 3478, socket.AF_INET, socket.SOCK_DGRAM)
        servers = [item[4] for item in candidates if udp.public_endpoint(item[4][0], item[4][1])]
        endpoint, samples = udp.audit_mappings(sock, servers)
        require(endpoint is not None)
        return sock, Endpoint(*endpoint)
    except BaseException:
        sock.close()
        raise


class ConnectedPeer:
    def __init__(self, sock, address): self.sock, self.address = sock, address
    def fileno(self): return self.sock.fileno()
    def recvfrom(self, size): return self.sock.recvfrom(size)
    def sendto(self, data, address):
        require(address == self.address)
        return self.sock.send(data)


def hello(sock, endpoint, own_nonce, other_nonce, deadline):
    require(deadline - time.monotonic() >= 20)
    raw = udp.exchange(sock, (endpoint.ip, endpoint.port), bytes.fromhex(own_nonce[:32]), bytes.fromhex(other_nonce[:32]), 20)
    require(raw['valid_peer_port_mismatches'] == 0 and raw['other_peer_ports'] == [])
    return HelloStats(raw['hello_received'], raw['ack_received'], raw['sent'])


def route(endpoint):
    result = subprocess.run(['/sbin/route', '-n', 'get', endpoint.ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5, check=True, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    return parse_route(result.stdout)


def write_file(path, value, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(canonical(value) + '\n')
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def save_private(plan):
    directory = Path(tempfile.mkdtemp(prefix='netdump-private-', dir=os.environ['RUNNER_TEMP']))
    require(directory.stat().st_mode & 0o777 == 0o700 and directory.stat().st_uid == os.geteuid())
    write_file(directory / 'discovery-plan.json', plan.record(), 0o600)


def discover(ctx, token, cert, nonce64, *, main_path):
    require(context_binding(ctx) and ctx['role'] == 'intel' and hexadecimal(nonce64))
    with bounded_session() as hard_deadline:
        deadline = operation_deadline(hard_deadline, time.monotonic())
        fingerprint = reports.cert_fingerprint(cert)
        core, network = source_identity(main_path)
        require(peer(ctx, token, 'intel', deadline) is None)
        receiver_id, offered = wait_peer(ctx, token, 'receiver', ('offer',), deadline)
        exact(offered, ('scope', 'phase', 'offer', 'offer_digest'))
        require(offered['scope'] == SCOPE and offered['phase'] == 'offer')
        offer = match_offer(offered['offer'], ctx, fingerprint, core, dict(network))
        require(offered['offer_digest'] == offer.digest())
        sock, endpoint = open_socket(offer.endpoint.port)
        owner = CheckOwner(ctx, token, 'intel', hard_deadline)
        try:
            require(sock.getsockname()[1] == offer.endpoint.port)
            address = (offer.endpoint.ip, offer.endpoint.port)
            sock.connect(address)
            source = private_ipv4(sock.getsockname()[0])
            gateway, interface = route(offer.endpoint)
            settings = NetdumpSettings(offer.endpoint.ip, gateway, offer.endpoint.port, nonce64[:16])
            plan = DiscoveryPlan(offer, nonce64, endpoint, source, interface, settings, None)
            public = plan.public_fact()
            owner.publish(public, deadline)
            stats = hello(ConnectedPeer(sock, address), offer.endpoint, nonce64, offer.nonce, deadline)
            plan = DiscoveryPlan(offer, nonce64, endpoint, source, interface, settings, stats)
            public = plan.public_fact()
            owner.publish(public, deadline)
            _, acknowledged = wait_peer(ctx, token, 'receiver', ('plan_ack',), deadline, receiver_id)
            validate_ack(acknowledged, offer, public)
            save_private(plan)
            owner.publish(public, deadline, complete=True)
            return plan
        except Exception:
            raise DiscoveryFailure(owner.cleanup()) from None
        finally:
            sock.close()


def serve_discovery(ctx, token, cert, *, main_path):
    require(context_binding(ctx) and ctx['role'] == 'receiver')
    with bounded_session() as hard_deadline:
        deadline = operation_deadline(hard_deadline, time.monotonic())
        fingerprint = reports.cert_fingerprint(cert)
        core, network = source_identity(main_path)
        require(peer(ctx, token, 'receiver', deadline) is None)
        sock, endpoint = open_socket(0)
        owner = CheckOwner(ctx, token, 'receiver', hard_deadline)
        public = {'scope': SCOPE, 'phase': 'failed'}
        try:
            offer = ReceiverOffer(context_binding(ctx), secrets.token_hex(16), endpoint, sock.getsockname()[1], fingerprint, core, network)
            public = {'scope': SCOPE, 'phase': 'offer', 'offer': offer.record(), 'offer_digest': offer.digest()}
            owner.publish(public, deadline)
            host_id, ready = wait_peer(ctx, token, 'intel', ('probe_ready',), deadline)
            validate_host_fact(ready, offer)
            stats = hello(sock, Endpoint.from_record(ready['intel_public_endpoint']), offer.nonce, ready['nonce'], deadline)
            _, plan = wait_peer(ctx, token, 'intel', ('plan',), deadline, host_id)
            validate_host_fact(plan, offer, expected_nonce=ready['nonce'])
            require(plan_base(ready) == plan_base(plan))
            public = ack_fact(offer, plan, stats)
            owner.publish(public, deadline, complete=True)
            return public
        except Exception:
            raise DiscoveryFailure(owner.cleanup()) from None
        finally:
            sock.close()


def main():
    token = os.environ.pop('GITHUB_TOKEN', '')
    cert = os.environ.pop('KDP_REPORT_CERT', '').encode()
    result, code = {'scope': SCOPE, 'status': 'failed', 'cleanup': 'not_created'}, 1
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in ('discover', 'receiver') and token and cert)
        ctx = udp.validate_context()
        path = Path(__file__).with_name('reboot-recovery.py')
        if sys.argv[1] == 'discover':
            result = discover(ctx, token, cert, secrets.token_hex(32), main_path=path).public_fact()
        else:
            result = serve_discovery(ctx, token, cert, main_path=path)
        code = 0
    except DiscoveryFailure as error:
        result['cleanup'] = error.cleanup
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        pass
    output = Path(os.environ['RUNNER_TEMP']) / 'debug'
    output.mkdir(exist_ok=True)
    require(not output.is_symlink())
    write_file(output / 'netdump-discovery.json', result, 0o644)
    print(canonical(result), flush=True)
    return code


if __name__ == '__main__': sys.exit(main())
