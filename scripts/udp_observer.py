"""Observe bounded exchanges without changing transport acceptance or I/O errors."""
import struct

CATEGORIES = ('length_invalid', 'magic_invalid', 'nonce_mismatch', 'kind_invalid', 'sequence_invalid',
              'valid_nonce_other_ip', 'valid_nonce_same_ip_other_port', 'exact_peer')


def require(condition):
    if not condition: raise ValueError('udp_observer_invalid')


def empty_counts(): return {'total': 0, 'received_bytes': 0, **{key: 0 for key in CATEGORIES}}


def validate_counts(value):
    require(type(value) is dict and set(value) == set(('total', 'received_bytes') + CATEGORIES))
    require(all(type(item) is int and item >= 0 for item in value.values()) and
            sum(value[key] for key in CATEGORIES) == value['total'] and
            (value['total'] != 0 or value['received_bytes'] == 0))
    return dict(value)


class Observer:
    """Count recvfrom results after socket filtering; retain no received payloads."""
    def __init__(self, transport, peer, own_nonce, peer_nonce, *, packet, max_packets=None):
        require(type(own_nonce) is bytes and type(peer_nonce) is bytes and len(own_nonce) == len(peer_nonce) == 16 and own_nonce != peer_nonce)
        require(isinstance(packet, struct.Struct) and (max_packets is None or type(max_packets) is int and max_packets > 0))
        self.transport, self.peer, self.own_nonce, self.peer_nonce = transport, peer, own_nonce, peer_nonce
        self.packet, self.max_packets = packet, max_packets
        self.counts, self.sent_sequences = empty_counts(), set()

    def fileno(self): return self.transport.fileno()

    def record_sent(self, packet, address, sent):
        if address == self.peer and sent == len(packet) and len(packet) == self.packet.size:
            magic, kind, sender, receiver, sequence = self.packet.unpack(packet)
            if magic == b'KDP1' and kind == 1 and sender == self.own_nonce and receiver == self.peer_nonce and sequence != 0:
                if len(self.sent_sequences) < 280 or sequence in self.sent_sequences:
                    self.sent_sequences.add(sequence)

    def sendto(self, packet, address):
        sent = self.transport.sendto(packet, address)
        self.record_sent(packet, address, sent)
        return sent

    def recvfrom(self, size):
        require(self.max_packets is None or self.counts['total'] < self.max_packets)
        packet, address = self.transport.recvfrom(size)
        self.counts['total'] += 1
        self.counts['received_bytes'] += len(packet)
        if len(packet) != self.packet.size: category = 'length_invalid'
        else:
            magic, kind, sender, receiver, sequence = self.packet.unpack(packet)
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
