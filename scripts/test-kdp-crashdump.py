import hashlib
import unittest

import kdp_crashdump as k


PREFIX = b'VZ_SYNTHETIC_NON_KERNEL\n'
NAME = 'synthetic-123'
WRQ = b'\x00\x02synthetic-123\x00octet\x00features\x00\x00\x00\x00\x01\x00\x00\x05\x7e'
ACK0 = b'\x00\x04\x00\x00\x00\x00'
ACK1 = b'\x00\x04\x00\x00\x00\x01'
ACK2 = b'\x00\x04\x00\x00\x00\x02'


class Crashdump(unittest.TestCase):
    def receiver(self, **kwargs):
        return k.Receiver(NAME, PREFIX, **kwargs)

    def test_pinned_xnu_variable_wrq_offset_and_six_byte_data_header(self):
        self.assertEqual(k.encode_wrq(NAME), WRQ)
        self.assertEqual(WRQ[2:16], b'synthetic-123\x00')
        self.assertEqual(k.encode_data(0x01020304, b'abc'), b'\x00\x03\x01\x02\x03\x04abc')
        self.assertEqual(k.encode_eof(0x01020304), b'\x00\x07\x01\x02\x03\x04')
        self.assertEqual(k.decode_ack(ACK2), 2)
        for packet in (b'', ACK2[:-1], ACK2 + b'\x00', b'\x00\x03\x00\x00\x00\x02', None):
            self.assertIsNone(k.decode_ack(packet))

    def test_transfer_negotiates_512_and_exact_duplicates_do_not_append_or_reset(self):
        r = self.receiver()
        self.assertEqual(r.state, 'await_wrq')
        self.assertEqual(r.receive(WRQ), ACK0)
        self.assertEqual(r.state, 'receiving')
        first = k.encode_data(1, PREFIX + b'A' * (512 - len(PREFIX)))
        self.assertEqual(r.receive(first), ACK1)
        self.assertEqual(r.receive(WRQ), ACK0)
        self.assertEqual(r.receive(first), ACK1)
        self.assertEqual(r.byte_count, 512)
        self.assertEqual(r.receive(k.encode_data(2, b'xyz')), ACK2)
        self.assertEqual(r.receive(first), ACK1)
        self.assertEqual(r.receive(k.encode_eof(3)), b'\x00\x04\x00\x00\x00\x03')
        self.assertEqual(r.state, 'complete')
        expected = PREFIX + b'A' * (512 - len(PREFIX)) + b'xyz'
        self.assertEqual(r.data, expected)
        self.assertEqual(r.byte_count, 515)
        self.assertEqual(r.digest, hashlib.sha256(expected).hexdigest())
        self.assertIsNone(r.error)
        self.assertEqual(r.receive(k.encode_eof(3)), b'\x00\x04\x00\x00\x00\x03')
        for packet in (WRQ, first, k.encode_eof(2), b'\xff\xff', bytearray(k.encode_eof(3))):
            self.assertIsNone(r.receive(packet))
        self.assertEqual(r.data, expected)
        self.assertEqual(r.state, 'complete')

    def test_future_packets_drop_without_changing_contiguous_sequence(self):
        r = self.receiver()
        self.assertEqual(r.receive(WRQ), ACK0)
        for packet in (k.encode_data(2, PREFIX), k.encode_eof(2)):
            self.assertIsNone(r.receive(packet))
            self.assertEqual(r.state, 'receiving')
            self.assertEqual(r.data, b'')
        self.assertEqual(r.receive(k.encode_data(1, PREFIX)), ACK1)
        self.assertEqual(r.receive(k.encode_eof(2)), ACK2)

    def test_malformed_conflicting_or_unbounded_input_fails_closed(self):
        cases = [([k.encode_data(1, b'not-the-required-prefix')], 'prefix_mismatch'),
                 ([b'\x00\x03\x00\x00\x00\x01' + PREFIX + b'x' * 512], 'packet_invalid'),
                 ([k.encode_data(1, PREFIX), k.encode_data(1, PREFIX + b'x')], 'block_conflict'),
                 ([k.encode_eof(1)], 'empty_transfer'),
                 ([b'\x00\x07\x00\x00\x00\x01x'], 'packet_invalid'),
                 ([b'\x00\x06\x00\x00\x00\x01'], 'opcode_unsupported'),
                 ([b'\x00'], 'packet_invalid'),
                 ([b'\x00\x03\x00\x00\x00\x01'], 'packet_invalid'),
                 ([k.encode_data(0, PREFIX)], 'block_conflict'),
                 ([k.encode_wrq('other-name')], 'wrq_mismatch'),
                 ([k.encode_wrq(NAME, features=0)], 'wrq_mismatch')]
        for packets, error in cases:
            with self.subTest(error=error, packets=packets):
                r = self.receiver()
                self.assertEqual(r.receive(WRQ), ACK0)
                for packet in packets[:-1]: self.assertEqual(r.receive(packet), ACK1)
                self.assertIsNone(r.receive(packets[-1]))
                self.assertEqual(r.state, 'failed')
                self.assertEqual(r.error.value, error)
                before = r.data
                self.assertIsNone(r.receive(WRQ))
                self.assertEqual(r.data, before)
        r = self.receiver(max_bytes=len(PREFIX))
        self.assertEqual(r.receive(WRQ), ACK0)
        self.assertEqual(r.receive(k.encode_data(1, PREFIX)), ACK1)
        self.assertIsNone(r.receive(k.encode_data(2, b'x')))
        self.assertEqual(r.error.value, 'size_limit')
        self.assertEqual(r.data, PREFIX)

    def test_exact_total_limit_can_complete_but_next_byte_cannot(self):
        r = self.receiver()
        self.assertEqual(r.receive(WRQ), ACK0)
        full = PREFIX + b'x' * (12288 - len(PREFIX))
        for index in range(24):
            ack = r.receive(k.encode_data(index + 1, full[index * 512:(index + 1) * 512]))
            self.assertEqual(k.decode_ack(ack), index + 1)
        self.assertEqual(r.byte_count, 12288)
        self.assertEqual(r.receive(k.encode_eof(25)), b'\x00\x04\x00\x00\x00\x19')
        self.assertEqual(r.data, full)

    def test_first_request_and_encoder_boundaries(self):
        for packet in (WRQ + b'x', WRQ.replace(b'octet', b'netascii'), k.encode_wrq('other'), k.encode_data(1, PREFIX)):
            r = self.receiver()
            self.assertIsNone(r.receive(packet))
            self.assertEqual(r.state, 'failed')
            self.assertEqual(r.byte_count, 0)
        self.assertEqual(self.receiver().receive(k.encode_wrq(NAME, features=3, max_packet=1406)), ACK0)
        for name in ('', 'a\x00b', '../x', '/x', 'a\\b', '\u00e9', 'x' * 256):
            with self.assertRaises(ValueError): k.encode_wrq(name)
        for block in (-1, 2**32, True):
            with self.assertRaises(ValueError): k.encode_eof(block)
            with self.assertRaises(ValueError): k.encode_data(block, PREFIX)
            with self.assertRaises(ValueError): k.encode_wrq(NAME, features=block)
            with self.assertRaises(ValueError): k.encode_wrq(NAME, max_packet=block)
        self.assertEqual(len(k.encode_data(1, b'x' * 512)), 518)
        for payload in (b'x' * 513, 'x', bytearray(b'x')):
            with self.assertRaises(ValueError): k.encode_data(1, payload)
        for prefix, size in ((b'', 12288), (b'x' * 513, 12288), (PREFIX, 1), (PREFIX, 12289), (PREFIX, True)):
            with self.assertRaises(ValueError): k.Receiver(NAME, prefix, max_bytes=size)


if __name__ == '__main__':
    unittest.main()
