from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re

import kdp_crashdump as wire
import recovery_nvram_panic as panic

PROTOCOL = 'netdump-capture-v1'
PRIME_KEYS = ('binding', 'nonce', 'baseline_boot_uuid', 'boot_uuid', 'core_identity', 'cert_fingerprint', 'recovery_check_id')
SCOPE_KEYS = PRIME_KEYS + ('intent_sha256', 'helper_sha256', 'helper_pid', 'tracer_pid')
UUID = re.compile(r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}')
TERMINATIONS = ('eof', 'limit', 'invalid', 'idle', 'deadline')


def require(condition):
    if not condition: raise ValueError('netdump_capture_invalid')


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def hexadecimal(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def positive(value):
    return type(value) is int and value > 0


def copied(value):
    return json.loads(json.dumps(value))


@dataclass(frozen=True)
class CaptureScope:
    binding: str
    nonce: str
    baseline_boot_uuid: str
    boot_uuid: str
    core_identity: str
    cert_fingerprint: str
    recovery_check_id: int
    intent_sha256: str
    helper_sha256: str
    helper_pid: int
    tracer_pid: int

    def __post_init__(self):
        require(type(self.binding) is str and re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,4}/[0-9a-f]{40}', self.binding))
        require(all(hexadecimal(getattr(self, key)) for key in ('nonce', 'core_identity', 'cert_fingerprint', 'intent_sha256', 'helper_sha256')))
        require(all(type(value) is str and UUID.fullmatch(value) for value in (self.baseline_boot_uuid, self.boot_uuid)))
        require(self.baseline_boot_uuid != self.boot_uuid and positive(self.recovery_check_id))
        require(all(positive(value) and value < 2**31 for value in (self.helper_pid, self.tracer_pid)) and self.helper_pid != self.tracer_pid)

    def record(self): return {key: getattr(self, key) for key in SCOPE_KEYS}

    @classmethod
    def from_record(cls, value):
        exact(value, SCOPE_KEYS)
        return cls(**value)

    @classmethod
    def from_trigger(cls, prime_record, intent_sha256, trigger):
        exact(prime_record, PRIME_KEYS)
        exact(trigger, ('scope', 'helper_sha256', 'helper_pid', 'tracer_pid', 'ready'))
        expected = {'binding': prime_record['binding'], 'nonce': prime_record['nonce'], 'baseline': prime_record['baseline_boot_uuid'],
                    'source_identity': prime_record['core_identity'], 'debug_boot_uuid': prime_record['boot_uuid']}
        exact(trigger['scope'], expected)
        require(trigger['ready'] is True and trigger['scope'] == expected)
        return cls.from_record({**prime_record, 'intent_sha256': intent_sha256,
                                **{key: trigger[key] for key in ('helper_sha256', 'helper_pid', 'tracer_pid')}})


def classify_kernel_fragment(data, nonce64, helper_pid):
    require(type(data) is bytes and hexadecimal(nonce64) and positive(helper_pid) and helper_pid < 2**31)
    if not data or len(data) > 12288:
        return {'status': 'empty' if not data else 'oversized', 'encoding': None, 'terminator_present': None,
                'freshness': 'unverified', 'completeness': 'unknown', 'packed_tail_bytes': 0, 'pid_matches': None}
    result = panic.classify_candidates([('raw', data)], nonce64)
    header = panic.HEADER.match(data)
    pid_matches = None
    if header:
        pid = re.search(rb'dtrace: panic action at probe pid([1-9][0-9]*):', header.group(0))
        pid_matches = pid is not None and pid.group(1) == str(helper_pid).encode('ascii')
    if result['status'] == 'fresh_fragment' and pid_matches is not True:
        result.update(status='pid_mismatch', freshness='unverified')
    return {**result, 'pid_matches': pid_matches}


class FragmentStream:
    def __init__(self, filename, required_prefix=b'panic('):
        self._receiver = wire.Receiver(filename, required_prefix, max_bytes=12288, paniclog=True)
        self._forensic = b''
        self._termination = None
        self._eof_accepted = False
        self._pending_eof_ack = None

    @property
    def data(self): return self._receiver.data

    @property
    def forensic(self): return self._forensic

    @property
    def termination(self): return self._termination

    @property
    def eof_accepted(self): return self._eof_accepted

    @property
    def pending_eof_ack(self): return self._pending_eof_ack

    def receive(self, packet):
        self._pending_eof_ack = None
        if self.termination is not None:
            if self.termination == 'eof': self._pending_eof_ack = self._receiver.receive(packet)
            return None
        ack = self._receiver.receive(packet)
        if self._receiver.state == wire.State.FAILED:
            self._termination = 'limit' if self._receiver.error == wire.Error.SIZE_LIMIT else 'invalid'
            self._forensic = packet[:4096] if type(packet) is bytes else b''
            return None
        if self._receiver.state == wire.State.COMPLETE:
            self._eof_accepted, self._termination, self._pending_eof_ack = True, 'eof', ack
            return None
        return ack

    def finish(self, reason):
        require(type(reason) is str and reason in ('idle', 'deadline', 'limit'))
        if self.termination is None: self._termination = reason

    def public_fact(self):
        return {'byte_count': len(self.data), 'body_sha256': hashlib.sha256(self.data).hexdigest(),
                'eof_accepted': self.eof_accepted, 'termination': self.termination}


def kernel_result(scope, stream):
    require(type(scope) is CaptureScope and type(stream) is FragmentStream and stream.termination in TERMINATIONS)
    classification = classify_kernel_fragment(stream.data, scope.nonce, scope.helper_pid)
    value = {'protocol': PROTOCOL, 'scope': scope.record(),
             'status': 'fresh_fragment' if classification['freshness'] == 'verified' else 'unverified',
             'freshness': classification['freshness'], 'completeness': 'unknown',
             **stream.public_fact(), 'classification': classification}
    return validate_result(value, scope)


def validate_result(value, scope):
    require(type(scope) is CaptureScope)
    exact(value, ('protocol', 'scope', 'status', 'freshness', 'completeness', 'byte_count', 'body_sha256',
                  'eof_accepted', 'termination', 'classification'))
    require(value['protocol'] == PROTOCOL and CaptureScope.from_record(value['scope']) == scope and
            type(value['byte_count']) is int and 0 <= value['byte_count'] <= 12288 and hexadecimal(value['body_sha256']) and
            type(value['eof_accepted']) is bool and value['termination'] in TERMINATIONS and
            value['eof_accepted'] == (value['termination'] == 'eof') and value['completeness'] == 'unknown')
    classification = value['classification']
    exact(classification, ('status', 'encoding', 'terminator_present', 'freshness', 'completeness', 'packed_tail_bytes', 'pid_matches'))
    require(classification['status'] in ('fresh_fragment', 'pid_mismatch', 'truncated', 'ambiguous', 'nonce_missing', 'uuid_missing',
                                        'uuid_mismatch', 'unrecognized', 'empty') and
            classification['encoding'] in (None, 'raw') and
            (classification['terminator_present'] is None or type(classification['terminator_present']) is bool) and
            (classification['pid_matches'] is None or type(classification['pid_matches']) is bool) and
            type(classification['packed_tail_bytes']) is int and classification['packed_tail_bytes'] == 0 and
            classification['completeness'] == 'unknown')
    fresh = classification['status'] == 'fresh_fragment'
    require(value['status'] == ('fresh_fragment' if fresh else 'unverified') and
            value['freshness'] == classification['freshness'] == ('verified' if fresh else 'unverified'))
    status = classification['status']
    if status == 'empty':
        require(value['byte_count'] == 0 and not value['eof_accepted'] and
                value['body_sha256'] == hashlib.sha256(b'').hexdigest())
    else:
        require(value['byte_count'] > 0)
    if status in ('empty', 'unrecognized'):
        require(classification['encoding'] is None and classification['terminator_present'] is None and classification['pid_matches'] is None)
    elif status == 'truncated':
        require(classification['encoding'] == 'raw' and classification['terminator_present'] is False and classification['pid_matches'] is None)
    else:
        require(classification['encoding'] == 'raw' and type(classification['terminator_present']) is bool and type(classification['pid_matches']) is bool)
    if fresh: require(classification['pid_matches'] is True)
    if status == 'pid_mismatch': require(classification['pid_matches'] is False)
    return copied(value)


def _peer(value):
    exact(value, ('ip', 'port'))
    require(type(value['ip']) is str and type(value['port']) is int and 1 <= value['port'] <= 65535)
    try: address = ipaddress.IPv4Address(value['ip'])
    except ipaddress.AddressValueError: raise ValueError('netdump_capture_invalid') from None
    require(str(address) == value['ip'] and address.is_global and not address.is_multicast)
    return dict(value)


def make_armed(scope, *, prime_proof_sha256, offer_digest, peer, receiver_check_id):
    require(type(scope) is CaptureScope and hexadecimal(prime_proof_sha256) and hexadecimal(offer_digest) and
            positive(receiver_check_id) and receiver_check_id != scope.recovery_check_id)
    return {'protocol': PROTOCOL, 'phase': 'armed', 'scope': scope.record(), 'prime_proof_sha256': prime_proof_sha256,
            'offer_digest': offer_digest, 'peer': _peer(peer), 'receiver_check_id': receiver_check_id}


def validate_armed(value, scope, *, prime_proof_sha256, offer_digest, peer, receiver_check_id):
    exact(value, ('protocol', 'phase', 'scope', 'prime_proof_sha256', 'offer_digest', 'peer', 'receiver_check_id'))
    expected = make_armed(scope, prime_proof_sha256=prime_proof_sha256, offer_digest=offer_digest, peer=peer, receiver_check_id=receiver_check_id)
    require(CaptureScope.from_record(value['scope']) == scope and _peer(value['peer']) == expected['peer'] and
            positive(value['receiver_check_id']) and value == expected)
    return copied(value)
