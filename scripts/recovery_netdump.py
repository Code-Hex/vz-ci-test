"""Actions-only userspace discovery; no boot settings writes or kernel packets."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
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
PRIME_TRANSPORT = 'userspace_udp_only'
UUID = re.compile(r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}')
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
class BootBaseline:
    baseline_boot_uuid: str
    nondebug_token_count: int
    nondebug_sha256: str

    def __post_init__(self):
        require(type(self.baseline_boot_uuid) is str and UUID.fullmatch(self.baseline_boot_uuid))
        require(type(self.nondebug_token_count) is int and 0 <= self.nondebug_token_count <= 512 and hexadecimal(self.nondebug_sha256))

    def profile(self):
        return {'status': 'observed', 'debug_mask': None, 'nondebug_token_count': self.nondebug_token_count,
                'nondebug_sha256': self.nondebug_sha256}

    def record(self): return {'baseline_boot_uuid': self.baseline_boot_uuid, 'boot_argument_profile': self.profile()}

    @classmethod
    def from_profile(cls, boot_uuid, profile):
        exact(profile, ('status', 'debug_mask', 'nondebug_token_count', 'nondebug_sha256'))
        require(profile['status'] == 'observed' and profile['debug_mask'] is None)
        return cls(boot_uuid, profile['nondebug_token_count'], profile['nondebug_sha256'])

    @classmethod
    def from_record(cls, value):
        exact(value, ('baseline_boot_uuid', 'boot_argument_profile'))
        return cls.from_profile(value['baseline_boot_uuid'], value['boot_argument_profile'])


@dataclass(frozen=True)
class ReceiverOffer:
    binding: str
    nonce: str
    endpoint: Endpoint
    local_port: int
    cert_fingerprint: str
    core_identity: str
    network_sources: tuple
    purpose: str = 'discovery'

    def __post_init__(self):
        require(type(self.binding) is str and re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}', self.binding))
        require(hexadecimal(self.nonce, 32) and type(self.endpoint) is Endpoint and self.endpoint.port != 41139)
        require(type(self.local_port) is int and 1 <= self.local_port <= 65535)
        require(hexadecimal(self.cert_fingerprint) and hexadecimal(self.core_identity))
        require(type(self.network_sources) is tuple and len(self.network_sources) == 4)
        require(all(type(pair) is tuple and len(pair) == 2 for pair in self.network_sources))
        require(tuple(key for key, value in self.network_sources) == NETWORK_KEYS and
                all(hexadecimal(value) for key, value in self.network_sources))
        require(type(self.purpose) is str and self.purpose in ('discovery', 'prime'))

    def record(self):
        return {'binding': self.binding, 'nonce': self.nonce, 'endpoint': self.endpoint.record(), 'local_port': self.local_port,
                'cert_fingerprint': self.cert_fingerprint, 'core_identity': self.core_identity, 'network_sources': dict(self.network_sources),
                'purpose': self.purpose}

    def digest(self): return digest(self.record())

    @classmethod
    def from_record(cls, value):
        exact(value, ('binding', 'nonce', 'endpoint', 'local_port', 'cert_fingerprint', 'core_identity', 'network_sources', 'purpose'))
        exact(value['network_sources'], NETWORK_KEYS)
        return cls(value['binding'], value['nonce'], Endpoint.from_record(value['endpoint']), value['local_port'],
                   value['cert_fingerprint'], value['core_identity'], tuple((key, value['network_sources'][key]) for key in NETWORK_KEYS), value['purpose'])


@dataclass(frozen=True)
class DiscoveryPlan:
    offer: ReceiverOffer
    nonce: str
    intel_endpoint: Endpoint
    source_ipv4: str
    interface: str
    settings: NetdumpSettings
    stats: HelloStats | None
    baseline: BootBaseline | None = None

    def __post_init__(self):
        require(type(self.offer) is ReceiverOffer and hexadecimal(self.nonce) and type(self.intel_endpoint) is Endpoint)
        require(self.nonce[:32] != self.offer.nonce)
        private_ipv4(self.source_ipv4)
        require(type(self.interface) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,15}', self.interface))
        require(type(self.settings) is NetdumpSettings and self.settings.receiver_ipv4 == self.offer.endpoint.ip and
                self.settings.port == self.offer.endpoint.port and self.settings.corename == self.nonce[:16])
        require(self.stats is None or type(self.stats) is HelloStats)
        require((self.offer.purpose == 'prime' and type(self.baseline) is BootBaseline) or
                (self.offer.purpose == 'discovery' and self.baseline is None))

    def record(self):
        return {'offer': self.offer.record(), 'nonce': self.nonce, 'intel_endpoint': self.intel_endpoint.record(),
                'source_ipv4': self.source_ipv4, 'interface': self.interface, 'settings': self.settings.record(),
                'stats': self.stats.record() if self.stats else None, 'baseline': self.baseline.record() if self.baseline else None}

    @classmethod
    def from_record(cls, value):
        exact(value, ('offer', 'nonce', 'intel_endpoint', 'source_ipv4', 'interface', 'settings', 'stats', 'baseline'))
        return cls(ReceiverOffer.from_record(value['offer']), value['nonce'], Endpoint.from_record(value['intel_endpoint']),
                   value['source_ipv4'], value['interface'], NetdumpSettings.from_record(value['settings']),
                   HelloStats.from_record(value['stats']) if value['stats'] is not None else None,
                   BootBaseline.from_record(value['baseline']) if value['baseline'] is not None else None)

    def public_fact(self):
        result = {'scope': SCOPE, 'phase': 'plan' if self.stats else 'probe_ready', 'binding': self.offer.binding,
                  'nonce': self.nonce, 'receiver_offer_digest': self.offer.digest(), 'receiver_nonce': self.offer.nonce,
                  'intel_public_endpoint': self.intel_endpoint.record(), 'local_port': self.settings.port,
                  'receiver_endpoint': self.offer.endpoint.record(), 'settings_sha256': self.settings.digest(),
                  'sourceIP_sha256': hashlib.sha256(self.source_ipv4.encode('ascii')).hexdigest(),
                  'gateway_sha256': hashlib.sha256(self.settings.router_ipv4.encode('ascii')).hexdigest(),
                  'interface_sha256': hashlib.sha256(self.interface.encode('ascii')).hexdigest(),
                  'baseline': self.baseline.record() if self.baseline else None, 'purpose': self.offer.purpose,
                  'cert_fingerprint': self.offer.cert_fingerprint, 'core_identity': self.offer.core_identity,
                  'network_sources': dict(self.offer.network_sources)}
        if self.stats: result['stats'] = self.stats.record()
        return result

    def digest(self): return digest(self.public_fact())


def context_binding(ctx):
    exact(ctx, ('run', 'attempt', 'sha', 'role', 'port_mode'))
    require(all(type(ctx[key]) is str for key in ctx))
    require(ctx['role'] in ('intel', 'receiver') and ctx['port_mode'] == 'kernel-source')
    binding = '/'.join((ctx['run'], ctx['attempt'], ctx['sha']))
    require(re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}', binding))
    return binding


def match_offer(value, ctx, fingerprint, core, network, purpose='discovery'):
    offer = ReceiverOffer.from_record(value)
    require(offer.binding == context_binding(ctx) and offer.cert_fingerprint == fingerprint and
            offer.core_identity == core and dict(offer.network_sources) == network and offer.purpose == purpose)
    return offer


def validate_host_fact(value, offer, expected_nonce=None):
    keys = ('scope', 'phase', 'binding', 'nonce', 'receiver_offer_digest', 'receiver_nonce', 'intel_public_endpoint',
            'local_port', 'receiver_endpoint', 'settings_sha256', 'sourceIP_sha256', 'gateway_sha256',
            'interface_sha256', 'baseline', 'purpose', 'cert_fingerprint', 'core_identity', 'network_sources')
    require(type(value) is dict and value.get('phase') in ('probe_ready', 'plan'))
    exact(value, keys + (('stats',) if value['phase'] == 'plan' else ()))
    require(value['scope'] == SCOPE and value['binding'] == offer.binding and hexadecimal(value['nonce']) and
            value['nonce'][:32] != offer.nonce and (expected_nonce is None or value['nonce'] == expected_nonce))
    require(value['receiver_offer_digest'] == offer.digest() and value['receiver_nonce'] == offer.nonce and
            Endpoint.from_record(value['receiver_endpoint']) == offer.endpoint and type(value['local_port']) is int and value['local_port'] == offer.endpoint.port)
    Endpoint.from_record(value['intel_public_endpoint'])
    require(value['cert_fingerprint'] == offer.cert_fingerprint and value['core_identity'] == offer.core_identity and
            value['network_sources'] == dict(offer.network_sources) and value['purpose'] == offer.purpose)
    if offer.purpose == 'prime': BootBaseline.from_record(value['baseline'])
    else: require(value['baseline'] is None)
    require(all(hexadecimal(value[key]) for key in ('settings_sha256', 'sourceIP_sha256', 'gateway_sha256', 'interface_sha256')))
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


@dataclass(frozen=True)
class PrimeScope:
    binding: str
    nonce: str
    baseline_boot_uuid: str
    boot_uuid: str
    core_identity: str
    cert_fingerprint: str
    recovery_check_id: int

    def __post_init__(self):
        require(type(self.binding) is str and re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}', self.binding))
        require(all(hexadecimal(value) for value in (self.nonce, self.core_identity, self.cert_fingerprint)))
        require(all(type(value) is str and UUID.fullmatch(value) for value in (self.baseline_boot_uuid, self.boot_uuid)))
        require(self.baseline_boot_uuid != self.boot_uuid and type(self.recovery_check_id) is int and self.recovery_check_id > 0)

    def record(self):
        return {key: getattr(self, key) for key in ('binding', 'nonce', 'baseline_boot_uuid', 'boot_uuid',
                                                  'core_identity', 'cert_fingerprint', 'recovery_check_id')}

    @classmethod
    def from_record(cls, value):
        exact(value, ('binding', 'nonce', 'baseline_boot_uuid', 'boot_uuid', 'core_identity', 'cert_fingerprint', 'recovery_check_id'))
        return cls(**value)


def prime_scope(value):
    return value if type(value) is PrimeScope else PrimeScope.from_record(value)


def checked_control(value, b1_plan):
    exact(value, ('status', 'settings_sha256', 'full_profile', 'remaining_profile'))
    require(value['status'] == 'observed' and value['settings_sha256'] == b1_plan['settings_sha256'])
    baseline = BootBaseline.from_record(b1_plan['baseline'])
    for profile in (value['full_profile'], value['remaining_profile']):
        exact(profile, ('status', 'debug_mask', 'nondebug_token_count', 'nondebug_sha256'))
        require(profile['status'] == 'observed' and type(profile['debug_mask']) is int and profile['debug_mask'] == 0x22040 and
                type(profile['nondebug_token_count']) is int and 0 <= profile['nondebug_token_count'] <= 512 and hexadecimal(profile['nondebug_sha256']))
    remaining, full = value['remaining_profile'], value['full_profile']
    require(remaining['nondebug_token_count'] == baseline.nondebug_token_count and remaining['nondebug_sha256'] == baseline.nondebug_sha256 and
            full['nondebug_token_count'] == remaining['nondebug_token_count'] + 4)
    return json.loads(canonical(value))


def checked_core_facts(facts, scope, b1_plan):
    require(type(facts) is dict and facts.get('current_boot_uuid') == scope.boot_uuid and
            type(facts.get('active_debug_mask')) is int and facts['active_debug_mask'] == 0x22040 and
            facts.get('active_bootargs_status') == 'observed_debug' and facts.get('bootplist_restored') is True)
    restoration, states = facts.get('bootplist_restore'), facts.get('bootplist_file_states')
    exact(restoration, ('data', 'preboot')); exact(states, ('data', 'preboot'))
    for name in ('data', 'preboot'):
        exact(restoration[name], ('bytes', 'metadata', 'timestamps'))
        require(all(value is True for value in restoration[name].values()) and states[name] in ('original', 'staged'))
    events = facts.get('owner_events')
    require(type(events) is list and 3 <= len(events) <= 5)
    filtered, seen = [], set()
    for event in events:
        require(type(event) is dict and event.get('event') in ('request', 'staged', 'bootplist_inflight', 'bootplist_staged', 'intent') and
                event['event'] not in seen and event.get('source_identity') == scope.core_identity and event.get('actual_boot_uuid') == scope.baseline_boot_uuid)
        seen.add(event['event'])
        item = {key: event[key] for key in ('event', 'source_identity', 'actual_boot_uuid')}
        if event['event'] == 'bootplist_staged':
            stage = event.get('bootplist_stage')
            exact(stage, ('data', 'preboot', 'metadata_preserved'))
            require(stage['data'] == stage['preboot'] == 'staged' and stage['metadata_preserved'] is True)
            item['bootplist_stage'] = stage
        filtered.append(item)
    require({'staged', 'bootplist_staged', 'intent'} <= seen)
    result = {key: facts[key] for key in ('current_boot_uuid', 'active_debug_mask', 'active_bootargs_status',
                                        'bootplist_restored', 'bootplist_restore', 'bootplist_file_states')}
    result['owner_events'] = filtered
    result['netdump_active_control'] = checked_control(facts.get('netdump_active_control'), b1_plan)
    return json.loads(canonical(result))


def core_snapshot(check, scope, b1_plan):
    scope = prime_scope(scope)
    baseline = BootBaseline.from_record(b1_plan['baseline'])
    require(b1_plan['purpose'] == 'prime' and baseline.baseline_boot_uuid == scope.baseline_boot_uuid and
            b1_plan['binding'] == scope.binding and b1_plan['nonce'] == scope.nonce and b1_plan['core_identity'] == scope.core_identity and
            b1_plan['cert_fingerprint'] == scope.cert_fingerprint)
    run, attempt, sha = scope.binding.split('/')
    require(type(check) is dict and type(check.get('id')) is int and check['id'] == scope.recovery_check_id and
            check.get('name') == 'Runner recovery ' + run and check.get('head_sha') == sha and check.get('external_id') == scope.binding and
            type(check.get('app')) is dict and check['app'].get('id') == 15368 and check['app'].get('slug') == 'github-actions' and
            check.get('details_url') == 'https://github.com/Code-Hex/vz-ci-test/runs/' + str(scope.recovery_check_id) and
            check.get('status') == 'in_progress' and check.get('conclusion') is None)
    output = check.get('output', {})
    require(type(output) is dict and output.get('title') == 'Boot core recovered' and output.get('text') in (None, '') and
            type(output.get('summary')) is str and len(output['summary']) <= 58000)
    summary = json.loads(output['summary'])
    require(type(summary) is dict and summary.get('protocol') == 'vz-recovery-v1' and summary.get('phase') == 'boot_core' and
            summary.get('binding') == scope.binding and summary.get('nonce') == scope.nonce and
            summary.get('baseline_boot_uuid') == scope.baseline_boot_uuid and summary.get('current_boot_uuid') == scope.boot_uuid and
            summary.get('cert_fingerprint') == scope.cert_fingerprint and summary.get('debug_boot') is True and
            summary.get('debug_source') == 'bootplist' and summary.get('after_debug_boot') == 'netdump-prime' and summary.get('trigger') == 'reboot-quick')
    return {'check_id': scope.recovery_check_id, 'summary_sha256': digest(summary),
            'facts': checked_core_facts(summary.get('debug_boot_facts'), scope, b1_plan)}


def prime_packet_nonce(scope, role, receiver_nonce):
    require(role in ('intel', 'receiver') and hexadecimal(receiver_nonce, 32))
    seed = 'netdump-prime/' + role + '/' + scope.nonce + '/' + scope.boot_uuid + '/' + receiver_nonce
    return hashlib.sha256(seed.encode('ascii')).hexdigest()[:32]


def validate_prime_host(value, offer, b1_plan, expected_scope=None):
    require(type(value) is dict and value.get('phase') in ('probe_ready', 'plan'))
    keys = ('protocol', 'scope', 'phase', 'offer_digest', 'b1_plan_sha256', 'core_summary_sha256', 'intel_public_endpoint',
            'local_port', 'receiver_endpoint', 'settings_sha256', 'sourceIP_sha256', 'gateway_sha256', 'interface_sha256',
            'network_sources', 'packet_nonce', 'receiver_packet_nonce')
    exact(value, keys + (('stats',) if value['phase'] == 'plan' else ()))
    scope = PrimeScope.from_record(value['scope'])
    require(expected_scope is None or scope == prime_scope(expected_scope))
    require(offer.purpose == 'prime' and value['protocol'] == 'netdump-prime-v1' and value['offer_digest'] == offer.digest() and
            value['b1_plan_sha256'] == digest(b1_plan) and scope.binding == offer.binding and scope.nonce == b1_plan['nonce'] and
            scope.core_identity == offer.core_identity and scope.cert_fingerprint == offer.cert_fingerprint and
            scope.baseline_boot_uuid == BootBaseline.from_record(b1_plan['baseline']).baseline_boot_uuid)
    Endpoint.from_record(value['intel_public_endpoint'])
    require(type(value['local_port']) is int and value['local_port'] == offer.endpoint.port and
            Endpoint.from_record(value['receiver_endpoint']) == offer.endpoint and value['network_sources'] == dict(offer.network_sources) and
            hexadecimal(value['core_summary_sha256']))
    for key in ('settings_sha256', 'sourceIP_sha256', 'gateway_sha256', 'interface_sha256'):
        require(value[key] == b1_plan[key] and hexadecimal(value[key]))
    require(value['packet_nonce'] == prime_packet_nonce(scope, 'intel', offer.nonce) and
            value['receiver_packet_nonce'] == prime_packet_nonce(scope, 'receiver', offer.nonce) and
            value['packet_nonce'] != value['receiver_packet_nonce'])
    if value['phase'] == 'plan': HelloStats.from_record(value['stats'])
    return json.loads(canonical(value))


def prime_host_fact(plan, scope, endpoint, snapshot, stats=None):
    b1 = plan.public_fact()
    value = {'protocol': 'netdump-prime-v1', 'scope': scope.record(), 'phase': 'plan' if stats else 'probe_ready',
             'offer_digest': plan.offer.digest(), 'b1_plan_sha256': digest(b1), 'core_summary_sha256': snapshot['summary_sha256'],
             'intel_public_endpoint': endpoint.record(), 'local_port': plan.settings.port,
             'receiver_endpoint': plan.offer.endpoint.record(), 'network_sources': dict(plan.offer.network_sources),
             'packet_nonce': prime_packet_nonce(scope, 'intel', plan.offer.nonce),
             'receiver_packet_nonce': prime_packet_nonce(scope, 'receiver', plan.offer.nonce)}
    for key in ('settings_sha256', 'sourceIP_sha256', 'gateway_sha256', 'interface_sha256'): value[key] = b1[key]
    if stats: value['stats'] = stats.record()
    return validate_prime_host(value, plan.offer, b1, scope)


def validate_prime_transition(probe, final, offer, b1_plan):
    ready = validate_prime_host(probe, offer, b1_plan)
    result = validate_prime_host(final, offer, b1_plan)
    require(ready['phase'] == 'probe_ready' and result['phase'] == 'plan' and plan_base(ready) == plan_base(result))
    return result


def make_prime_proof(offer, b1_plan, host_plan, stats, snapshot, receiver_id, host_id):
    value = {'protocol': 'netdump-prime-v1', 'phase': 'prime_ack', 'transport': PRIME_TRANSPORT, 'scope': host_plan['scope'],
             'offer': offer.record(), 'b1_plan': b1_plan, 'b1_plan_sha256': digest(b1_plan), 'host_plan': host_plan,
             'receiver_stats': stats.record(), 'core_snapshot': snapshot, 'receiver_check_id': receiver_id, 'host_check_id': host_id}
    return validate_prime_proof(value, PrimeScope.from_record(host_plan['scope']), snapshot['facts']['netdump_active_control'])


def validate_prime_proof(proof, expected_scope, active_control):
    exact(proof, ('protocol', 'phase', 'transport', 'scope', 'offer', 'b1_plan', 'b1_plan_sha256', 'host_plan',
                  'receiver_stats', 'core_snapshot', 'receiver_check_id', 'host_check_id'))
    scope = prime_scope(expected_scope)
    require(proof['protocol'] == 'netdump-prime-v1' and proof['phase'] == 'prime_ack' and proof['transport'] == PRIME_TRANSPORT and
            PrimeScope.from_record(proof['scope']) == scope)
    offer = ReceiverOffer.from_record(proof['offer'])
    b1_plan = validate_host_fact(proof['b1_plan'], offer, expected_nonce=scope.nonce)
    require(offer.purpose == 'prime' and b1_plan['phase'] == 'plan' and proof['b1_plan_sha256'] == digest(b1_plan))
    host = validate_prime_host(proof['host_plan'], offer, b1_plan, scope)
    require(host['phase'] == 'plan')
    HelloStats.from_record(proof['receiver_stats'])
    snapshot = proof['core_snapshot']
    exact(snapshot, ('check_id', 'summary_sha256', 'facts'))
    require(type(snapshot['check_id']) is int and snapshot['check_id'] == scope.recovery_check_id and
            snapshot['summary_sha256'] == host['core_summary_sha256'] and hexadecimal(snapshot['summary_sha256']))
    facts = checked_core_facts(snapshot['facts'], scope, b1_plan)
    require(facts == snapshot['facts'] and checked_control(active_control, b1_plan) == facts['netdump_active_control'])
    require(all(type(proof[key]) is int and proof[key] > 0 for key in ('receiver_check_id', 'host_check_id')) and
            len({proof['receiver_check_id'], proof['host_check_id'], scope.recovery_check_id}) == 3)
    require(len(canonical(proof)) <= 58000)
    return json.loads(canonical(proof))


def verify_prime_ack(ctx, token, proof, expected_scope, active_control, deadline):
    verified = validate_prime_proof(proof, expected_scope, active_control)
    require(context_binding(ctx) == verified['scope']['binding'])
    check = call(deadline, 'GET', '/check-runs/' + str(verified['receiver_check_id']), token)
    require(check.get('id') == verified['receiver_check_id'] and check_payload(check, ctx, 'receiver', prime=True) == verified)
    return verified


def waiting_fact(offer, b1_plan, accepted_probe=None, snapshot=None):
    value = {'protocol': 'netdump-prime-v1', 'phase': 'waiting_b2', 'transport': PRIME_TRANSPORT,
             'offer': offer.record(), 'b1_plan_sha256': digest(b1_plan), 'accepted_probe': accepted_probe,
             'accepted_probe_sha256': digest(accepted_probe) if accepted_probe is not None else None, 'core_snapshot': snapshot}
    return validate_waiting(value, offer, b1_plan)


def validate_waiting(value, offer, b1_plan, expected_probe=None):
    require(offer.purpose == 'prime' and validate_host_fact(b1_plan, offer)['phase'] == 'plan')
    exact(value, ('protocol', 'phase', 'transport', 'offer', 'b1_plan_sha256', 'accepted_probe', 'accepted_probe_sha256', 'core_snapshot'))
    require(value['protocol'] == 'netdump-prime-v1' and value['phase'] == 'waiting_b2' and value['transport'] == PRIME_TRANSPORT and
            ReceiverOffer.from_record(value['offer']) == offer and value['b1_plan_sha256'] == digest(b1_plan))
    if value['accepted_probe'] is None:
        require(value['accepted_probe_sha256'] is None and value['core_snapshot'] is None and expected_probe is None)
    else:
        probe = validate_prime_host(value['accepted_probe'], offer, b1_plan)
        require(probe['phase'] == 'probe_ready' and value['accepted_probe_sha256'] == digest(probe) and
                (expected_probe is None or probe == expected_probe))
        scope = PrimeScope.from_record(probe['scope'])
        snapshot = value['core_snapshot']
        exact(snapshot, ('check_id', 'summary_sha256', 'facts'))
        require(type(snapshot['check_id']) is int and snapshot['check_id'] == scope.recovery_check_id and
                snapshot['summary_sha256'] == probe['core_summary_sha256'] and hexadecimal(snapshot['summary_sha256']))
        require(checked_core_facts(snapshot['facts'], scope, b1_plan) == snapshot['facts'])
    return json.loads(canonical(value))


def check_attributes(ctx, role, prime=False, boot_uuid=None):
    name = 'Netdump ' + ('prime ' if prime else '') + ('plan' if role == 'intel' else 'receiver') + ' ' + ctx['run']
    external = ('netdump-prime/' if prime else 'netdump/') + role + '/' + context_binding(ctx)
    if prime and role == 'intel':
        require(type(boot_uuid) is str and UUID.fullmatch(boot_uuid))
        external += '/' + boot_uuid
    return name, external


def check_identity(check, ctx, role, *, prime=False, boot_uuid=None):
    if prime and role == 'intel' and boot_uuid is None:
        external = check.get('external_id')
        if type(external) is not str: return False
        boot_uuid = external.rsplit('/', 1)[-1]
        if not UUID.fullmatch(boot_uuid): return False
    name, external = check_attributes(ctx, role, prime, boot_uuid)
    number = check.get('id')
    return (type(number) is int and number > 0 and check.get('name') == name
            and check.get('head_sha') == ctx['sha'] and check.get('external_id') == external
            and type(check.get('app')) is dict and check['app'].get('id') == 15368 and check['app'].get('slug') == 'github-actions'
            and check.get('details_url') == 'https://github.com/Code-Hex/vz-ci-test/runs/' + str(number))


def select_check(listing, ctx, role, *, prime=False, boot_uuid=None):
    require(type(listing) is dict and type(listing.get('check_runs')) is list and type(listing.get('total_count')) is int)
    checks = listing['check_runs']
    require(len(checks) <= 100 and listing['total_count'] == len(checks) and all(type(item) is dict for item in checks))
    name = 'Netdump ' + ('prime ' if prime else '') + ('plan' if role == 'intel' else 'receiver') + ' ' + ctx['run']
    external = ('netdump-prime/' if prime else 'netdump/') + role + '/' + context_binding(ctx)
    matches = [item for item in checks if item.get('name') == name or item.get('external_id') == external or
               (prime and role == 'intel' and type(item.get('external_id')) is str and item['external_id'].startswith(external + '/'))]
    require(len(matches) <= 1)
    if not matches: return None
    require(check_identity(matches[0], ctx, role, prime=prime, boot_uuid=boot_uuid))
    return matches[0]


@contextmanager
def bounded_session(seconds=180, hard_deadline=None):
    started = time.monotonic()
    require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds > 0)
    if hard_deadline is not None:
        require(type(hard_deadline) in (int, float) and math.isfinite(hard_deadline))
        seconds = min(seconds, hard_deadline - started)
        if seconds <= 0: raise TimeoutError('discovery_deadline')
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    seconds = min(seconds, previous_timer[0]) if previous_timer[0] else seconds
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


def check_payload(check, ctx, role, *, prime=False, boot_uuid=None):
    require(check_identity(check, ctx, role, prime=prime, boot_uuid=boot_uuid))
    summary = check.get('output', {}).get('summary')
    require(type(summary) is str and len(summary) <= 16000)
    value = json.loads(summary)
    require(type(value) is dict and canonical(value) == summary)
    phase, status, conclusion = value.get('phase'), check.get('status'), check.get('conclusion')
    if prime:
        require(status == 'completed' and conclusion == 'neutral' and
                phase in (('probe_ready', 'plan') if role == 'intel' else ('waiting_b2', 'prime_ack')))
        return value
    if phase in ('offer', 'probe_ready'):
        require(status == 'in_progress' and conclusion is None)
    elif phase == 'plan_ack':
        require(role == 'receiver' and status == 'completed' and conclusion == 'success')
    else:
        require(role == 'intel' and phase == 'plan' and ((status == 'in_progress' and conclusion is None) or
                (status == 'completed' and conclusion == 'success')))
    return value


def peer(ctx, token, role, deadline, *, prime=False, boot_uuid=None):
    listed = call(deadline, 'GET', '/commits/' + ctx['sha'] + '/check-runs?filter=all&per_page=100', token)
    selected = select_check(listed, ctx, role, prime=prime, boot_uuid=boot_uuid)
    if selected is None: return None
    check = call(deadline, 'GET', '/check-runs/' + str(selected['id']), token)
    require(check.get('id') == selected['id'])
    value = check_payload(check, ctx, role, prime=prime, boot_uuid=boot_uuid)
    return check['id'], value


class DiscoveryFailure(ValueError):
    def __init__(self, cleanup):
        super().__init__('discovery_failed')
        self.cleanup = cleanup


def operation_deadline(hard_deadline, now):
    if hard_deadline - now <= 24: raise TimeoutError('discovery_deadline')
    return hard_deadline - 24


class CheckOwner:
    def __init__(self, ctx, token, role, hard_deadline, *, prime=False, boot_uuid=None):
        self.ctx, self.token, self.role, self.hard_deadline = ctx, token, role, hard_deadline
        self.check_id, self.attempted, self.latest = None, False, {'scope': SCOPE}
        self.prime, self.boot_uuid = prime, boot_uuid

    def publish(self, value, deadline, *, complete=False):
        self.latest = value
        summary = canonical(value)
        require(len(summary) <= 16000)
        payload = {'status': 'completed' if complete or self.prime else 'in_progress',
                   'output': {'title': 'Netdump discovery only', 'summary': summary, 'text': ''}}
        if self.prime: payload['conclusion'] = 'neutral'
        elif complete: payload['conclusion'] = 'success' if value.get('phase') in ('plan', 'plan_ack') else 'neutral'
        if self.check_id is None:
            require(not self.attempted)
            name, external = check_attributes(self.ctx, self.role, self.prime, self.boot_uuid)
            payload.update(name=name, head_sha=self.ctx['sha'], external_id=external)
            self.attempted = True
            created = call(deadline, 'POST', '/check-runs', self.token, payload)
            require(check_identity(created, self.ctx, self.role, prime=self.prime, boot_uuid=self.boot_uuid))
            self.check_id = created['id']
        else:
            call(deadline, 'PATCH', '/check-runs/' + str(self.check_id), self.token, payload)
        saved = call(deadline, 'GET', '/check-runs/' + str(self.check_id), self.token)
        require(check_identity(saved, self.ctx, self.role, prime=self.prime, boot_uuid=self.boot_uuid) and saved['id'] == self.check_id and
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


def wait_peer(ctx, token, role, phases, deadline, check_id=None, *, prime=False, boot_uuid=None):
    while time.monotonic() < deadline:
        result = peer(ctx, token, role, deadline, prime=prime, boot_uuid=boot_uuid)
        if result:
            number, value = result
            require(check_id is None or number == check_id)
            require(value.get('phase') in (('probe_ready', 'plan') if role == 'intel' else
                    (('waiting_b2', 'prime_ack') if prime else ('offer', 'plan_ack'))))
            if value['phase'] in phases: return number, value
        time.sleep(.5)
    raise TimeoutError('discovery_deadline')


def source_identity(main_path):
    network = tuple((key, hashlib.sha256(Path(path).read_bytes()).hexdigest()) for key, path in zip(NETWORK_KEYS,
                    (__file__, udp.__file__, udp.wire.__file__, reports.__file__)))
    return sources.identity(main_path), network


def mapping_result(endpoint, samples, expected=None):
    require(endpoint is not None)
    result = Endpoint(*endpoint)
    if expected is not None:
        require(result == expected and type(samples) is list and len(samples) > 0)
        primary = samples[0]['server_ip']
        require(all(Endpoint(item['ip'], item['port']) == expected for item in samples
                    if item['server_ip'] == primary and item['state'] == 'observed'))
    return result


def mapping(sock, expected=None):
    candidates = socket.getaddrinfo('stun.cloudflare.com', 3478, socket.AF_INET, socket.SOCK_DGRAM)
    servers = [item[4] for item in candidates if udp.public_endpoint(item[4][0], item[4][1])]
    endpoint, samples = udp.audit_mappings(sock, servers)
    return mapping_result(endpoint, samples, expected)


def open_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', port))
        return sock, mapping(sock)
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


def discover(ctx, token, cert, nonce64, *, main_path, purpose='discovery', baseline=None):
    require(context_binding(ctx) and ctx['role'] == 'intel' and hexadecimal(nonce64))
    require((purpose == 'prime' and type(baseline) is BootBaseline) or (purpose == 'discovery' and baseline is None))
    with bounded_session() as hard_deadline:
        deadline = operation_deadline(hard_deadline, time.monotonic())
        fingerprint = reports.cert_fingerprint(cert)
        core, network = source_identity(main_path)
        require(peer(ctx, token, 'intel', deadline) is None)
        receiver_id, offered = wait_peer(ctx, token, 'receiver', ('offer',), deadline)
        exact(offered, ('scope', 'phase', 'offer', 'offer_digest'))
        require(offered['scope'] == SCOPE and offered['phase'] == 'offer')
        offer = match_offer(offered['offer'], ctx, fingerprint, core, dict(network), purpose)
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
            plan = DiscoveryPlan(offer, nonce64, endpoint, source, interface, settings, None, baseline)
            public = plan.public_fact()
            owner.publish(public, deadline)
            stats = hello(ConnectedPeer(sock, address), offer.endpoint, nonce64, offer.nonce, deadline)
            plan = DiscoveryPlan(offer, nonce64, endpoint, source, interface, settings, stats, baseline)
            public = plan.public_fact()
            owner.publish(public, deadline)
            _, acknowledged = wait_peer(ctx, token, 'receiver', ('plan_ack',), deadline, receiver_id)
            validate_ack(acknowledged, offer, public)
            owner.publish(public, deadline, complete=True)
            return plan
        except Exception:
            raise DiscoveryFailure(owner.cleanup()) from None
        finally:
            sock.close()


def serve_b1(ctx, token, fingerprint, core, network, sock, endpoint, deadline, hard_deadline, purpose):
    owner = CheckOwner(ctx, token, 'receiver', hard_deadline)
    try:
        offer = ReceiverOffer(context_binding(ctx), secrets.token_hex(16), endpoint, sock.getsockname()[1], fingerprint, core, network, purpose)
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
        return offer, plan, public
    except Exception:
        raise DiscoveryFailure(owner.cleanup()) from None


def serve_discovery(ctx, token, cert, *, main_path):
    require(context_binding(ctx) and ctx['role'] == 'receiver')
    with bounded_session() as hard_deadline:
        deadline = operation_deadline(hard_deadline, time.monotonic())
        fingerprint = reports.cert_fingerprint(cert)
        core, network = source_identity(main_path)
        require(peer(ctx, token, 'receiver', deadline) is None)
        sock, endpoint = open_socket(0)
        try:
            return serve_b1(ctx, token, fingerprint, core, network, sock, endpoint, deadline, hard_deadline, 'discovery')[2]
        finally:
            sock.close()


def prime(ctx, token, cert, plan, boot_uuid, recovery_check_id, *, main_path, hard_deadline):
    require(context_binding(ctx) and ctx['role'] == 'intel' and type(plan) is DiscoveryPlan and plan.offer.purpose == 'prime' and plan.stats is not None)
    with bounded_session(hard_deadline=hard_deadline) as hard:
        deadline = operation_deadline(hard, time.monotonic())
        core, network = source_identity(main_path)
        match_offer(plan.offer.record(), ctx, reports.cert_fingerprint(cert), core, dict(network), 'prime')
        scope = PrimeScope(plan.offer.binding, plan.nonce, plan.baseline.baseline_boot_uuid, boot_uuid, core, plan.offer.cert_fingerprint, recovery_check_id)
        require(peer(ctx, token, 'intel', deadline, prime=True, boot_uuid=boot_uuid) is None)
        snapshot = core_snapshot(call(deadline, 'GET', '/check-runs/' + str(recovery_check_id), token), scope, plan.public_fact())
        receiver_id, waiting = wait_peer(ctx, token, 'receiver', ('waiting_b2',), deadline, prime=True)
        validate_waiting(waiting, plan.offer, plan.public_fact())
        require(waiting['accepted_probe'] is None)
        sock, endpoint = open_socket(plan.settings.port)
        owner = CheckOwner(ctx, token, 'intel', hard, prime=True, boot_uuid=boot_uuid)
        try:
            require(sock.getsockname()[1] == plan.settings.port)
            address = (plan.offer.endpoint.ip, plan.offer.endpoint.port)
            sock.connect(address)
            source = private_ipv4(sock.getsockname()[0])
            gateway, interface = route(plan.offer.endpoint)
            require(source == plan.source_ipv4 and gateway == plan.settings.router_ipv4 and interface == plan.interface)
            probe = prime_host_fact(plan, scope, endpoint, snapshot)
            owner.publish(probe, deadline)
            while True:
                _, accepted = wait_peer(ctx, token, 'receiver', ('waiting_b2',), deadline, receiver_id, prime=True)
                validated = validate_waiting(accepted, plan.offer, plan.public_fact())
                if validated['accepted_probe'] is not None:
                    validate_waiting(validated, plan.offer, plan.public_fact(), probe)
                    require(validated['core_snapshot'] == snapshot)
                    break
                time.sleep(.5)
            stats = hello(ConnectedPeer(sock, address), plan.offer.endpoint, probe['packet_nonce'], probe['receiver_packet_nonce'], deadline)
            final = prime_host_fact(plan, scope, endpoint, snapshot, stats)
            owner.publish(final, deadline)
            _, proof = wait_peer(ctx, token, 'receiver', ('prime_ack',), deadline, receiver_id, prime=True)
            require(proof.get('host_check_id') == owner.check_id and proof.get('receiver_check_id') == receiver_id and proof.get('host_plan') == final)
            return verify_prime_ack(ctx, token, proof, scope, snapshot['facts']['netdump_active_control'], deadline)
        except Exception:
            raise DiscoveryFailure(owner.cleanup()) from None
        finally:
            sock.close()


def serve_prime(ctx, token, cert, *, main_path):
    require(context_binding(ctx) and ctx['role'] == 'receiver')
    with bounded_session(1080) as hard:
        deadline = operation_deadline(hard, time.monotonic())
        fingerprint = reports.cert_fingerprint(cert)
        core, network = source_identity(main_path)
        require(peer(ctx, token, 'receiver', deadline) is None and peer(ctx, token, 'receiver', deadline, prime=True) is None)
        sock, endpoint = open_socket(0)
        owner = CheckOwner(ctx, token, 'receiver', hard, prime=True)
        try:
            offer, b1_plan, _ = serve_b1(ctx, token, fingerprint, core, network, sock, endpoint, deadline, hard, 'prime')
            owner.publish(waiting_fact(offer, b1_plan), deadline)
            while True:
                require(deadline - time.monotonic() >= 60)
                require(mapping(sock, offer.endpoint) == offer.endpoint)
                candidate = peer(ctx, token, 'intel', deadline, prime=True)
                if candidate is not None:
                    host_id, probe = candidate
                    validate_prime_host(probe, offer, b1_plan)
                    require(probe['phase'] == 'probe_ready')
                    scope = PrimeScope.from_record(probe['scope'])
                    snapshot = core_snapshot(call(deadline, 'GET', '/check-runs/' + str(scope.recovery_check_id), token), scope, b1_plan)
                    require(snapshot['summary_sha256'] == probe['core_summary_sha256'] and deadline - time.monotonic() >= 60)
                    owner.publish(waiting_fact(offer, b1_plan, probe, snapshot), deadline)
                    break
                time.sleep(1)
            stats = hello(sock, Endpoint.from_record(probe['intel_public_endpoint']), probe['receiver_packet_nonce'], probe['packet_nonce'], deadline)
            _, final = wait_peer(ctx, token, 'intel', ('plan',), deadline, host_id, prime=True, boot_uuid=scope.boot_uuid)
            validate_prime_transition(probe, final, offer, b1_plan)
            proof = make_prime_proof(offer, b1_plan, final, stats, snapshot, owner.check_id, host_id)
            owner.publish(proof, deadline, complete=True)
            return proof
        except DiscoveryFailure:
            if not owner.attempted: raise
            raise DiscoveryFailure(owner.cleanup()) from None
        except Exception:
            raise DiscoveryFailure(owner.cleanup()) from None
        finally:
            sock.close()


def main():
    token = os.environ.pop('GITHUB_TOKEN', '')
    cert = os.environ.pop('KDP_REPORT_CERT', '').encode()
    result, code = {'scope': SCOPE, 'status': 'failed', 'cleanup': 'not_created'}, 1
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in ('discover', 'receiver', 'prime-receiver') and token and cert)
        ctx = udp.validate_context()
        path = Path(__file__).with_name('reboot-recovery.py')
        if sys.argv[1] == 'discover':
            plan = discover(ctx, token, cert, secrets.token_hex(32), main_path=path)
            save_private(plan)
            result = plan.public_fact()
        elif sys.argv[1] == 'receiver':
            result = serve_discovery(ctx, token, cert, main_path=path)
        else:
            result = serve_prime(ctx, token, cert, main_path=path)
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
