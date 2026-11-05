"""Pure nonce-bound USDT probe identities and source fragments."""
from dataclasses import dataclass
import re


def _require(condition):
    if not condition: raise ValueError('invalid_usdt_probe')


@dataclass(frozen=True)
class ProbeSpec:
    nonce: str

    def __post_init__(self):
        _require(type(self.nonce) is str and re.fullmatch('[0-9a-f]{64}', self.nonce))

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
        _require(type(self.spec) is ProbeSpec and type(self.pid) is int and 0 < self.pid < 2**31)

    @property
    def fields(self): return (self.spec.provider + str(self.pid), 'helper', self.spec.function, 'observe')

    @property
    def selector(self): return ':'.join(self.fields)

    @property
    def predicate(self): return ' /pid == ' + str(self.pid) + ' && arg0 == 0x' + self.spec.argument + '/ '


def validate_header(raw, spec):
    _require(type(spec) is ProbeSpec)
    provider = spec.provider
    _require(type(raw) is bytes and len(raw) <= 65536)
    try: text = raw.decode('ascii')
    except UnicodeError: raise ValueError('invalid_usdt_probe') from None
    _require(re.search(r'^#define\s+' + re.escape(provider.upper()) + r'_OBSERVE\s*\(', text, re.M))
    return True


def provider_source(spec):
    _require(type(spec) is ProbeSpec)
    return ('provider ' + spec.provider + ' { probe observe(unsigned long long); };\n').encode()


def function_source(spec):
    _require(type(spec) is ProbeSpec)
    return ('__attribute__((noinline,used,visibility("default"))) void ' + spec.function + '(void) {\n    ' +
            spec.provider.upper() + '_OBSERVE(0x' + spec.argument + 'ULL);\n}\n').encode()


def parse_listing(raw, probe):
    _require(type(raw) is bytes and len(raw) <= 65536 and type(probe) is ProbeIdentity)
    try: lines = raw.decode('ascii').splitlines()
    except UnicodeError: raise ValueError('invalid_usdt_probe') from None
    _require(lines and lines[0].split() == ['ID', 'PROVIDER', 'MODULE', 'FUNCTION', 'NAME'])
    rows, identifiers = [line.split() for line in lines[1:] if line.strip()], set()
    _require(1 <= len(rows) <= 32)
    for row in rows:
        _require(len(row) == 5 and re.fullmatch('[1-9][0-9]*', row[0]) and row[0] not in identifiers and
                tuple(row[1:]) == probe.fields)
        identifiers.add(row[0])
    return len(rows)


def parse_hit(raw, probe):
    _require(type(probe) is ProbeIdentity and type(raw) is bytes)
    expected = 'HIT ' + str(probe.pid) + ' ' + ' '.join(probe.fields) + ' ' + probe.spec.argument + '\n'
    _require(raw == expected.encode())

