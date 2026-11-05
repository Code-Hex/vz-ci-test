"""Bounded, ACK-only crashdump wire model, without transport or filesystem access."""
from enum import Enum
import hashlib
import struct


class State(str, Enum):
    AWAIT_WRQ = 'await_wrq'
    RECEIVING = 'receiving'
    COMPLETE = 'complete'
    FAILED = 'failed'


class Error(str, Enum):
    PACKET_INVALID = 'packet_invalid'
    OPCODE_UNSUPPORTED = 'opcode_unsupported'
    WRQ_MISMATCH = 'wrq_mismatch'
    WRQ_REQUIRED = 'wrq_required'
    PREFIX_MISMATCH = 'prefix_mismatch'
    BLOCK_CONFLICT = 'block_conflict'
    SIZE_LIMIT = 'size_limit'
    EMPTY_TRANSFER = 'empty_transfer'


def _uint32(value):
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ValueError('uint32_invalid')
    return value


def _filename(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 255 or value in ('.', '..')
            or any(not 32 <= ord(char) <= 126 or char in '/\\' for char in value)):
        raise ValueError('filename_invalid')
    return value.encode('ascii')


def encode_wrq(filename, features=1, max_packet=1406):
    return (b'\x00\x02' + _filename(filename) + b'\x00octet\x00features\x00'
            + struct.pack('!II', _uint32(features), _uint32(max_packet)))


def encode_data(block, payload):
    if not isinstance(payload, bytes) or len(payload) > 512:
        raise ValueError('payload_invalid')
    return struct.pack('!HI', 3, _uint32(block)) + payload


def encode_paniclog_data(block, payload, filename, trailer):
    if (not isinstance(payload, bytes) or not 1 <= len(payload) <= 512 or
            not isinstance(trailer, bytes) or len(trailer) != len(_filename(filename)) + 1):
        raise ValueError('paniclog_payload_invalid')
    return encode_data(block, payload) + trailer


def encode_eof(block):
    return struct.pack('!HI', 7, _uint32(block))


def decode_ack(packet):
    if not isinstance(packet, bytes) or len(packet) != 6 or packet[:2] != b'\x00\x04':
        return None
    return struct.unpack('!I', packet[2:])[0]


class Receiver:
    def __init__(self, filename, required_prefix, max_bytes=12288, *, paniclog=False):
        self._request_prefix = b'\x00\x02' + _filename(filename) + b'\x00octet\x00features\x00'
        if (not isinstance(required_prefix, bytes) or not 1 <= len(required_prefix) <= 512
                or type(max_bytes) is not int or not len(required_prefix) <= max_bytes <= 12288 or type(paniclog) is not bool):
            raise ValueError('receiver_bounds_invalid')
        self._tail_bytes = len(_filename(filename)) + 1 if paniclog else 0
        self._prefix, self._limit = required_prefix, max_bytes
        self._data = bytearray()
        self._blocks = {}
        self._wrq = self._eof = None
        self.state, self.error = State.AWAIT_WRQ, None

    @property
    def data(self):
        return bytes(self._data)

    @property
    def byte_count(self):
        return len(self._data)

    @property
    def digest(self):
        return hashlib.sha256(self._data).hexdigest()

    def _fail(self, error):
        self.state, self.error = State.FAILED, error
        return None

    def receive(self, packet):
        if self.state == State.FAILED:
            return None
        if self.state == State.COMPLETE:
            return struct.pack('!HI', 4, self._eof) if isinstance(packet, bytes) and packet == encode_eof(self._eof) else None
        if not isinstance(packet, bytes) or len(packet) < 2:
            return self._fail(Error.PACKET_INVALID)
        opcode = struct.unpack('!H', packet[:2])[0]
        if opcode == 2:
            if self._wrq is not None:
                return b'\x00\x04\x00\x00\x00\x00' if packet == self._wrq else self._fail(Error.WRQ_MISMATCH)
            if not packet.startswith(self._request_prefix) or len(packet) != len(self._request_prefix) + 8:
                return self._fail(Error.WRQ_MISMATCH)
            self._wrq, self.state = packet, State.RECEIVING
            # The six-byte ACK0 advertises no optional features, limiting DATA to 512.
            return b'\x00\x04\x00\x00\x00\x00'
        if opcode not in (3, 7):
            return self._fail(Error.OPCODE_UNSUPPORTED)
        if self.state != State.RECEIVING:
            return self._fail(Error.WRQ_REQUIRED)
        if (len(packet) < 6 or (opcode == 7 and len(packet) != 6) or
                (opcode == 3 and not 1 <= len(packet) - 6 - self._tail_bytes <= 512)):
            return self._fail(Error.PACKET_INVALID)
        block = struct.unpack('!I', packet[2:6])[0]
        next_block = len(self._blocks) + 1
        if block > next_block:
            return None
        if opcode == 7:
            if block != next_block:
                return self._fail(Error.BLOCK_CONFLICT)
            if not self._data:
                return self._fail(Error.EMPTY_TRANSFER)
            self._eof, self.state = block, State.COMPLETE
        else:
            # Paniclog DATA includes a corename-sized tail outside its copied body.
            payload = packet[6:len(packet) - self._tail_bytes] if self._tail_bytes else packet[6:]
            if block < next_block:
                previous = self._blocks.get(block)
                if previous is None or self._data[previous[0]:previous[1]] != payload:
                    return self._fail(Error.BLOCK_CONFLICT)
            else:
                if block == 1 and not payload.startswith(self._prefix):
                    return self._fail(Error.PREFIX_MISMATCH)
                if len(self._data) + len(payload) > self._limit:
                    return self._fail(Error.SIZE_LIMIT)
                start = len(self._data)
                self._data.extend(payload)
                self._blocks[block] = (start, len(self._data))
        return struct.pack('!HI', 4, block)
