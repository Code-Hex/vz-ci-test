"""Fixed netdump settings and pure validation of one active bootargs capture."""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re

import recovery_bootargs as boot


DEBUG_MASK = 0x22040


@dataclass(frozen=True)
class NetdumpSettings:
    receiver_ipv4: str
    router_ipv4: str
    port: int
    corename: str

    def __post_init__(self):
        try:
            for value, receiver in ((self.receiver_ipv4, True), (self.router_ipv4, False)):
                if type(value) is not str:
                    raise ValueError
                address = ipaddress.IPv4Address(value)
                if (str(address) != value or address.is_unspecified or address.is_multicast or address.is_loopback
                        or address.is_reserved or int(address) < 0x01000000 or int(address) == 0xffffffff
                        or receiver and not address.is_global):
                    raise ValueError
            if type(self.port) is not int or not 1 <= self.port <= 65535 or self.port == 41139:
                raise ValueError
            if (type(self.corename) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,16}', self.corename)
                    or self.corename in ('.', '..')):
                raise ValueError
        except ValueError:
            raise ValueError('netdump_settings_invalid') from None

    def record(self):
        return {'receiver_ipv4': self.receiver_ipv4, 'router_ipv4': self.router_ipv4,
                'port': self.port, 'corename': self.corename}

    @classmethod
    def from_record(cls, record):
        if type(record) is not dict or set(record) != {'receiver_ipv4', 'router_ipv4', 'port', 'corename'}:
            raise ValueError('netdump_settings_invalid')
        return cls(**record)

    def tokens(self):
        return ('_panicd_ip=' + self.receiver_ipv4, '_router_ip=' + self.router_ipv4,
                'panicd_port=' + str(self.port), '_panicd_corename=' + self.corename)

    def digest(self):
        canonical = json.dumps(self.record(), sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        return hashlib.sha256(canonical).hexdigest()

    def strip_owned(self, raw):
        try:
            expected = {token.partition('=')[0]: token for token in self.tokens()}
            remaining, seen = [], set()
            for token in boot.text(raw).split():
                key = token.partition('=')[0].lstrip('-')
                if key in expected:
                    if token != expected[key] or key in seen:
                        raise ValueError
                    seen.add(key)
                else:
                    remaining.append(token)
            if seen != set(expected):
                raise ValueError
            return ' '.join(remaining)
        except ValueError:
            raise ValueError('netdump_active_control_invalid') from None


def active_control(raw, settings, baseline_profile):
    try:
        if (type(settings) is not NetdumpSettings or type(baseline_profile) is not dict or
                set(baseline_profile) != {'status', 'debug_mask', 'nondebug_token_count', 'nondebug_sha256'} or
                baseline_profile['status'] != 'observed' or baseline_profile['debug_mask'] is not None or
                type(baseline_profile['nondebug_token_count']) is not int or
                not 0 <= baseline_profile['nondebug_token_count'] <= 512 or
                type(baseline_profile['nondebug_sha256']) is not str or
                not re.fullmatch(r'[0-9a-f]{64}', baseline_profile['nondebug_sha256'])):
            raise ValueError
        captured = boot.text(raw)
        remaining = boot.boot_argument_profile(settings.strip_owned(captured))
        if (remaining['debug_mask'] != DEBUG_MASK or any(remaining[key] != baseline_profile[key]
                for key in ('nondebug_token_count', 'nondebug_sha256'))):
            raise ValueError
        tokens = [token for token in captured.split() if token.partition('=')[0].lstrip('-') != 'debug']
        canonical = json.dumps(tokens, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        full = {**remaining, 'nondebug_token_count': len(tokens), 'nondebug_sha256': hashlib.sha256(canonical).hexdigest()}
        return {'status': 'observed', 'settings_sha256': settings.digest(), 'full_profile': full, 'remaining_profile': remaining}
    except ValueError:
        raise ValueError('netdump_active_control_invalid') from None
