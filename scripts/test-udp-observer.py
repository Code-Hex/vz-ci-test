import json
import socket
import threading
import unittest

import kdp_udp_preflight as u
import recovery_netdump as n
import udp_observer as o


class Observation(unittest.TestCase):
    def observer(self, sock, peer, *, max_packets=None):
        return o.Observer(sock, peer, b'a' * 16, b'b' * 16, packet=u.PACKET, max_packets=max_packets)

    def test_common_validator_has_no_diagnostic_quota_and_rejects_invalid_data(self):
        counts = {**o.empty_counts(), 'total': 4097, 'received_bytes': 8194, 'length_invalid': 4097}
        self.assertEqual(o.validate_counts(counts), counts)
        for changed in ({**counts, 'total': True}, {**counts, 'raw': 'private'}, {**counts, 'received_bytes': -1},
                        {**counts, 'exact_peer': 1}):
            with self.assertRaises(ValueError): o.validate_counts(changed)

    def test_native_no_quota_and_caller_quota_are_distinct(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(('127.0.0.1', 0)); sender.bind(('127.0.0.1', 0)); receiver.settimeout(1)
            observer = self.observer(receiver, sender.getsockname())
            for _ in range(4100):
                sender.sendto(b'x', receiver.getsockname())
                self.assertEqual(observer.recvfrom(1024)[0], b'x')
            self.assertEqual(observer.fact()['total'], 4100)
            bounded = self.observer(receiver, sender.getsockname(), max_packets=1)
            sender.sendto(b'a', receiver.getsockname()); bounded.recvfrom(1024)
            sender.sendto(b'b', receiver.getsockname())
            with self.assertRaises(ValueError): bounded.recvfrom(1024)
            self.assertEqual(receiver.recvfrom(1024)[0], b'b')

    def test_native_packets_are_returned_unchanged_and_only_ack_uses_sent_sequence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as host, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            for sock in (host, peer, other): sock.bind(('127.0.0.1', 0)); sock.settimeout(1)
            observer = self.observer(host, peer.getsockname())
            packets = [b'bad', u.PACKET.pack(b'BAD1', 1, b'b' * 16, b'a' * 16, 1),
                       u.PACKET.pack(b'KDP1', 1, b'c' * 16, b'a' * 16, 1),
                       u.PACKET.pack(b'KDP1', 9, b'b' * 16, b'a' * 16, 1),
                       u.PACKET.pack(b'KDP1', 1, b'b' * 16, b'a' * 16, 999),
                       u.PACKET.pack(b'KDP1', 2, b'b' * 16, b'a' * 16, 7)]
            for packet in packets:
                other.sendto(packet, host.getsockname())
                self.assertEqual(observer.recvfrom(1024), (packet, other.getsockname()))
            for category in ('length_invalid', 'magic_invalid', 'nonce_mismatch', 'kind_invalid'):
                self.assertEqual(observer.fact()[category], 1)
            self.assertEqual(observer.fact()['valid_nonce_same_ip_other_port'], 1)
            self.assertEqual(observer.fact()['sequence_invalid'], 1)
            observer.sendto(u.PACKET.pack(b'KDP1', 2, b'a' * 16, b'b' * 16, 7), peer.getsockname())
            self.assertEqual(observer.sent_sequences, set())
            observer.sendto(u.PACKET.pack(b'KDP1', 1, b'a' * 16, b'b' * 16, 7), peer.getsockname())
            self.assertEqual(observer.sent_sequences, {7})
            other.sendto(packets[-1], host.getsockname()); observer.recvfrom(1024)
            self.assertEqual(observer.fact()['valid_nonce_same_ip_other_port'], 2)
            self.assertNotIn('127.0.0.1', json.dumps(observer.fact()))

    def test_native_foreign_ip_and_larger_recv_buffer_remain_observational(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(('127.0.0.1', 0)); sender.bind(('127.0.0.1', 0)); receiver.settimeout(1)
            observer = self.observer(receiver, ('8.8.8.8', sender.getsockname()[1]))
            packet = u.PACKET.pack(b'KDP1', 1, b'b' * 16, b'a' * 16, 1)
            sender.sendto(packet, receiver.getsockname())
            self.assertEqual(observer.recvfrom(1024), (packet, sender.getsockname()))
            self.assertEqual(observer.fact()['valid_nonce_other_ip'], 1)
            sender.sendto(b'x' * 2048, receiver.getsockname())
            self.assertEqual(len(observer.recvfrom(4096)[0]), 2048)
            self.assertEqual(observer.fact()['received_bytes'], 2048 + u.PACKET.size)
            self.assertEqual(observer.fact()['length_invalid'], 1)
            self.assertNotIn('127.0.0.1', json.dumps(observer.fact()))

    def test_native_io_errors_propagate_without_synthesizing_counts(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        observer = self.observer(sock, ('127.0.0.1', 9))
        sock.close()
        with self.assertRaises(OSError): observer.sendto(u.PACKET.pack(b'KDP1', 1, b'a' * 16, b'b' * 16, 1), observer.peer)
        with self.assertRaises(OSError): observer.recvfrom(1024)
        self.assertEqual(observer.sent_sequences, set())
        self.assertEqual(observer.fact(), o.empty_counts())

    def test_short_successful_send_is_not_a_successful_hello(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            observer = self.observer(sock, ('127.0.0.1', 9))
            packet = u.PACKET.pack(b'KDP1', 1, b'a' * 16, b'b' * 16, 1)
            observer.record_sent(packet, observer.peer, len(packet) - 1)
            self.assertEqual(observer.sent_sequences, set())
            observer.record_sent(packet, observer.peer, len(packet))
            self.assertEqual(observer.sent_sequences, {1})

    def test_native_connected_bridge_preserves_existing_exchange(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(('127.0.0.1', 0)); b.bind(('127.0.0.1', 0)); a.connect(b.getsockname())
            host = o.Observer(n.ConnectedPeer(a, b.getsockname()), b.getsockname(), b'a' * 16, b'b' * 16, packet=u.PACKET)
            receiver = o.Observer(b, a.getsockname(), b'b' * 16, b'a' * 16, packet=u.PACKET)
            results = []
            thread = threading.Thread(target=lambda: results.append(u.exchange(receiver, a.getsockname(), b'b' * 16, b'a' * 16, .2)))
            thread.start()
            results.append(u.exchange(host, b.getsockname(), b'a' * 16, b'b' * 16, .2))
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertTrue(all(result['hello_received'] and result['ack_received'] for result in results))
            self.assertTrue(host.fact()['exact_peer'] > 0)


if __name__ == '__main__': unittest.main()
