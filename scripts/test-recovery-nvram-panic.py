import base64
import unittest

import recovery_nvram_panic as panic

NONCE = 'a' * 64
UUID = '87453B1D-A163-31FA-B33B-0FB4BE78E6E8'
HEADER = ('panic(cpu 1 caller 0xffffff8000012345): dtrace: panic action at probe '
          'pid123:sample:vz_nonce_' + NONCE + ':entry (ecb 0xffffff8000001234)\n')
REPORT = (HEADER + 'Kernel UUID: ' + UUID + '\n').encode() + b'\0'
USDT_NONCE = '0123456789abcdef' * 4
USDT_HEADER = (b'panic(cpu 1 caller 0xffffff8000012345): dtrace: panic action at probe '
               b'vzobs0123456789abcdefp123:helper:vz_nonce_'
               b'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
               b':observe (ecb 0xffffff8000001234)\n')
USDT_REPORT = USDT_HEADER + b'Kernel UUID: 87453B1D-A163-31FA-B33B-0FB4BE78E6E8\n'
USDT_PACKED = base64.b64decode(
    '8LA7PUaN4XVQDDQOs9llOQiGN5vNZrMZB4PBYDHZjFZL6UBkujw8LutA8LA7PQaFx/T02w0K00Fw+VtcBtn1b/EcFpPNaDXbDZcLi8fkshkek8106DIbXpbr7Pqv++0el7+wmGxGq9luuFxYPCaXzbCYbEar2W64XFg8JpfNsJhsRqvZbrhcWDwml82wmGxGq9luuFxYPCaXzbq3eF6W28sgVHksBsHwZrPZbDbjYDAYDBaTzWgpxbIsd5fZoGo1SdSBcDdabSaMEVvBmG3WmsWMwZZwNhO2YEYhTVi84Yq2Ik4BAAAA')
USDT_UNTERMINATED_PACKED = base64.b64decode(
    '8LA7PUaN4XVQDDQOs9llOQiGN5vNZrMZB4PBYDHZjFZL6UBkujw8LutA8LA7PQaFx/T02w0K00Fw+VtcBtn1b/EcFpPNaDXbDZcLi8fkshkek8106DIbXpbr7Pqv++0el7+wmGxGq9luuFxYPCaXzbCYbEar2W64XFg8JpfNsJhsRqvZbrhcWDwml82wmGxGq9luuFxYPCaXzbq3eF6W28sgVHksBsHwZrPZbDbjYDAYDBaTzWgpxbIsd5fZoGo1SdSBcDdabSaMEVvBmG3WmsWMwZZwNhO2YEYhTVi84Yq2Ik6h1Wq1')


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


class UsdtPanicData(unittest.TestCase):
    def test_literal_raw_and_packa_have_the_same_freshness_metadata(self):
        for raw, encoding, terminated in ((USDT_REPORT, 'raw', False),
                                         (USDT_REPORT + b'\0', 'raw', True),
                                         (USDT_PACKED, 'packA', True),
                                         (USDT_UNTERMINATED_PACKED, 'packA', False)):
            with self.subTest(encoding=encoding, terminated=terminated):
                self.assertEqual(panic.classify_usdt(raw, USDT_NONCE, 123), {
                    'status': 'fresh_fragment', 'encoding': encoding, 'freshness': 'verified',
                    'completeness': 'unknown', 'terminator_present': terminated, 'packed_tail_bytes': 0})
        self.assertEqual(panic.unpack_a(USDT_PACKED).split(b'\0', 1)[0], USDT_REPORT)

    def test_selector_fields_and_actual_helper_pid_are_exact(self):
        changes = ((b'p123:', b'p124:'), (b'vzobs0123456789abcdefp', b'vzobs1123456789abcdefp'),
                   (b':helper:', b':other:'), (b':observe ', b':entry '),
                   (b'abcdef:observe', b'abcdee:observe'))
        for before, after in changes:
            with self.subTest(before=before):
                result = panic.classify_usdt(USDT_REPORT.replace(before, after), USDT_NONCE, 123)
                self.assertEqual(result['freshness'], 'unverified')
        self.assertEqual(panic.classify_usdt(USDT_REPORT, USDT_NONCE, 124)['freshness'], 'unverified')
        self.assertEqual(panic.classify_usdt(USDT_REPORT, USDT_NONCE[:-1] + 'e', 123)['freshness'], 'unverified')

    def test_pid_and_usdt_classifiers_never_accept_the_other_kind(self):
        pid = (HEADER.replace(NONCE, USDT_NONCE) + 'Kernel UUID: ' + UUID + '\n').encode()
        self.assertEqual(panic.classify_usdt(pid, USDT_NONCE, 123)['freshness'], 'unverified')
        self.assertEqual(panic.classify(USDT_REPORT, USDT_NONCE)['freshness'], 'unverified')
        self.assertEqual(panic.classify(USDT_PACKED, USDT_NONCE)['freshness'], 'unverified')
        self.assertEqual(panic.classify(REPORT, NONCE)['freshness'], 'verified')

    def test_uuid_header_and_line_termination_are_required(self):
        for raw in (USDT_REPORT.replace(UUID.encode(), b'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'),
                    USDT_HEADER, USDT_REPORT[:-1], b'prefix\n' + USDT_REPORT,
                    b'\0' + USDT_REPORT, USDT_REPORT.replace(b'panic(cpu ', b'panic(cpu -')):
            with self.subTest(raw=raw):
                self.assertEqual(panic.classify_usdt(raw, USDT_NONCE, 123)['freshness'], 'unverified')
        for suffix in (b'Kernel UUID: broken\n', b'Kernel UUID:', USDT_HEADER,
                       b'panic(cpu 2): another panic\n'):
            with self.subTest(suffix=suffix):
                self.assertEqual(panic.classify_usdt(USDT_REPORT + suffix, USDT_NONCE, 123)['status'], 'ambiguous')

    def test_nonce_or_uuid_after_nul_and_ignored_packed_tail_cannot_complete_a_fragment(self):
        for raw in (b'panic(cpu 1): old panic\0' + USDT_REPORT,
                    USDT_HEADER + b'\0Kernel UUID: ' + UUID.encode() + b'\n',
                    USDT_PACKED[:-7] + b'ABCDEF'):
            with self.subTest(raw=raw):
                self.assertEqual(panic.classify_usdt(raw, USDT_NONCE, 123)['freshness'], 'unverified')
        result = panic.classify_usdt(USDT_PACKED + b'ABC', USDT_NONCE, 123)
        self.assertEqual((result['freshness'], result['packed_tail_bytes']), ('verified', 3))

    def test_usdt_empty_oversized_and_invalid_inputs(self):
        for raw, status in ((b'', 'empty'), (b'x' * (panic.MAX_RAW + 1), 'oversized')):
            self.assertEqual(panic.classify_usdt(raw, USDT_NONCE, 123), {
                'status': status, 'encoding': None, 'freshness': 'unverified', 'completeness': 'unknown',
                'terminator_present': None, 'packed_tail_bytes': 0})
        for nonce, pid in (('bad', 123), (USDT_NONCE, True), (USDT_NONCE, 0),
                           (USDT_NONCE, -1), (USDT_NONCE, 2**31)):
            with self.subTest(nonce=nonce, pid=pid), self.assertRaises(ValueError):
                panic.classify_usdt(USDT_REPORT, nonce, pid)
        with self.assertRaises(TypeError): panic.classify_usdt('not bytes', USDT_NONCE, 123)


if __name__ == '__main__': unittest.main()
