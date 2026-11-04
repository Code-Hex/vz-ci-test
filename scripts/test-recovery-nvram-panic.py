import base64
import unittest

import recovery_nvram_panic as panic

NONCE = 'a' * 64
UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
HEADER = ('panic(cpu 1 caller 0xffffff8000012345): dtrace: panic action at probe '
          'pid123:sample:vz_nonce_' + NONCE + ':entry (ecb 0xffffff8000001234)\n')
REPORT = (HEADER + 'Kernel UUID: ' + UUID + '\n').encode() + b'\0'


class PanicData(unittest.TestCase):
    def test_packa_literal(self):
        self.assertEqual(panic.unpack_a(bytes.fromhex('41e19058341e91')), b'ABCDEFGH')

    def test_packed_report_fixture_and_truncated_prefix(self):
        raw = base64.b64decode(
            '8LA7PUaN4XVQDDQOs9llOQiGN5vNZrMZB4PBYDHZjFZL6UBkujw8LutA8LA7PQaFx/T02w0K00Fw+VtcBsHT5JhsppuH23B2WWfXf91v97j8DYfD4XA4HA6Hw+FwOBwOh8PhcDgcDofD4XA4HA6Hw+FwOBwOh8PhcDgcDofD4XA4HA6Hw+FwOBzWld10eR6EKo/FIBjebDabzWYcDAaDwWKyGS2lWJbl7jIbVK0miToQ7karzYQxYisYs81as5gx2BLOZsIWzCikCYs3XNFWxCkA')
        self.assertEqual(panic.classify(raw, NONCE), {'status': 'fresh_fragment', 'encoding': 'packA', 'freshness': 'verified', 'completeness': 'unknown', 'terminator_present': True, 'packed_tail_bytes': 0})
        self.assertNotEqual(panic.classify(raw[:-1], NONCE)['freshness'], 'verified')

    def test_unterminated_raw_fragment_still_proves_freshness(self):
        result = panic.classify(REPORT[:-1], NONCE)
        self.assertEqual(result['status'], 'fresh_fragment')
        self.assertEqual(result['freshness'], 'verified')
        self.assertFalse(result['terminator_present'])
        self.assertEqual(result['packed_tail_bytes'], 0)
        self.assertEqual(result['completeness'], 'unknown')

    def test_additional_malformed_or_partial_uuid_line_is_ambiguous(self):
        for suffix in (b'Kernel UUID: broken\n', b'Kernel UUID:'):
            with self.subTest(suffix=suffix):
                result = panic.classify(REPORT[:-1] + suffix, NONCE)
                self.assertEqual(result['freshness'], 'unverified')

    def test_additional_panic_header_is_ambiguous(self):
        result = panic.classify(REPORT[:-1] + b'panic(cpu 2 caller 0xff): other panic\n', NONCE)
        self.assertEqual(result['freshness'], 'unverified')

    def test_partial_uuid_line_cannot_prove_identity(self):
        cut = (HEADER + 'Kernel UUID: ' + UUID).encode()
        result = panic.classify(cut, NONCE)
        self.assertEqual(result['freshness'], 'unverified')
        self.assertEqual(result['status'], 'uuid_missing')

    def test_unterminated_packed_fragment_and_incomplete_tail(self):
        raw = base64.b64decode('8LA7PUaN4XVQDDQOs9llOQiGN5vNZrMZB4PBYDHZjFZL6UBkujw8LutA8LA7PQaFx/T02w0K00Fw+VtcBsHT5JhsppuH23B2WWfXf91v97j8DYfD4XA4HA6Hw+FwOBwOh8PhcDgcDofD4XA4HA6Hw+FwOBwOh8PhcDgcDofD4XA4HA6Hw+FwOBzWld10eR6EKo/FIBjebDabzWYcDAaDwWKyGS2lWJbl7jIbVK0miToQ7karzYQxYisYs81as5gx2BLOZsIWzCikCYs3XNFWxCmwWCwWi8VisVgsFovFYrFCQ0Q=')
        result = panic.classify(raw, NONCE)
        self.assertEqual((result['status'], result['freshness'], result['encoding']), ('fresh_fragment', 'verified', 'packA'))
        self.assertFalse(result['terminator_present'])
        self.assertEqual(result['packed_tail_bytes'], 3)

    def test_packa_requires_complete_group(self):
        with self.assertRaises(ValueError):
            panic.unpack_a(b'123456')

    def test_raw_report_verified(self):
        result = panic.classify(REPORT, NONCE)
        self.assertEqual(result['status'], 'fresh_fragment')
        self.assertEqual(result['freshness'], 'verified')
        self.assertEqual(result['completeness'], 'unknown')

    def test_nonce_and_uuid_must_be_exact(self):
        self.assertEqual(panic.classify(REPORT, 'b' * 64)['status'], 'nonce_missing')
        bad_uuid = REPORT.replace(UUID.encode(), b'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')
        self.assertEqual(panic.classify(bad_uuid, NONCE)['status'], 'uuid_mismatch')
        self.assertEqual(panic.classify(b'other header\n' + REPORT, NONCE)['freshness'], 'unverified')

    def test_truncated_and_invalid(self):
        self.assertEqual(panic.classify(REPORT[:-1], NONCE)['status'], 'fresh_fragment')
        self.assertEqual(panic.classify(b'', NONCE)['status'], 'empty')
        self.assertEqual(panic.classify(b'x' * (panic.MAX_RAW + 1), NONCE)['status'], 'oversized')
        with self.assertRaises(ValueError): panic.classify(REPORT, 'not-a-nonce')

    def test_multiple_valid_formats_are_ambiguous(self):
        candidates = [('raw', REPORT), ('packA', REPORT)]
        self.assertEqual(panic.classify_candidates(candidates, NONCE)['status'], 'ambiguous')


if __name__ == '__main__': unittest.main()
