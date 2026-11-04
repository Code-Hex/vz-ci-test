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
        self.assertEqual(panic.classify(raw, NONCE), {'status': 'verified', 'encoding': 'packA', 'completeness': 'unknown'})
        self.assertEqual(panic.classify(raw[:-1], NONCE)['status'], 'truncated')

    def test_packa_requires_complete_group(self):
        with self.assertRaises(ValueError):
            panic.unpack_a(b'123456')

    def test_raw_report_verified(self):
        result = panic.classify(REPORT, NONCE)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(result['completeness'], 'unknown')

    def test_nonce_and_uuid_must_be_exact(self):
        self.assertEqual(panic.classify(REPORT, 'b' * 64)['status'], 'nonce_missing')
        bad_uuid = REPORT.replace(UUID.encode(), b'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')
        self.assertEqual(panic.classify(bad_uuid, NONCE)['status'], 'uuid_mismatch')
        self.assertNotEqual(panic.classify(b'other header\n' + REPORT, NONCE)['status'], 'verified')

    def test_truncated_and_invalid(self):
        self.assertEqual(panic.classify(REPORT[:-1], NONCE)['status'], 'truncated')
        self.assertEqual(panic.classify(b'', NONCE)['status'], 'empty')
        self.assertEqual(panic.classify(b'x' * (panic.MAX_RAW + 1), NONCE)['status'], 'oversized')
        with self.assertRaises(ValueError): panic.classify(REPORT, 'not-a-nonce')

    def test_multiple_valid_formats_are_ambiguous(self):
        candidates = [('raw', REPORT), ('packA', REPORT)]
        self.assertEqual(panic.classify_candidates(candidates, NONCE)['status'], 'ambiguous')


if __name__ == '__main__': unittest.main()
