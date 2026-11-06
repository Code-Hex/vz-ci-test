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


SYSCALL_MARKER = 'vz-reboot-panic:' + USDT_NONCE + ':123'
SYSCALL_HEADER = (b'panic(cpu 1 caller 0xffffff8000012345): userspace panic: '
                  b'vz-reboot-panic:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:123\n')
SYSCALL_REPORT = SYSCALL_HEADER + b'Kernel UUID: 87453B1D-A163-31FA-B33B-0FB4BE78E6E8\n'
SYSCALL_PACKED = base64.b64decode(
    '8LA7PUaN4XVQDDQOs9llOQiGN5vNZrMZB4PBYDHZjFZL6UD1eVk+h4fHZRA87E6PdSC7viUvi99vegsedqfHOlhMNqPVbDdcLiwek8tmWEw2o9VsN1wuLB6Ty2ZYTDaj1Ww3XC4sHpPLZlhMNqPVbDdcLiwek8tmXUw2UyzLcneZDapWk0QdCHej1WbCGLEVjNlmrVnMGGwJZzNhC2YU0oTFG65oK+IUAAAAAAAAAA==')
SYSCALL_UNTERMINATED_PACKED = SYSCALL_PACKED[:-7]


class SyscallPanicData(unittest.TestCase):
    def classify(self, raw):
        return panic.classify_syscall(raw, USDT_NONCE, 123)

    def test_marker_is_exact_and_bounded_for_native_pid(self):
        self.assertEqual(panic.syscall_marker(USDT_NONCE, 123), SYSCALL_MARKER)
        self.assertEqual(panic.syscall_marker('f' * 64, 2**31 - 1),
                         'vz-reboot-panic:' + 'f' * 64 + ':2147483647')
        self.assertLess(len(panic.syscall_marker('f' * 64, 2**31 - 1).encode('ascii')), 128)

    def test_literal_raw_and_packa_have_exact_freshness_metadata(self):
        for raw, encoding, terminated in ((SYSCALL_REPORT, 'raw', False),
                                         (SYSCALL_REPORT + b'\0', 'raw', True),
                                         (SYSCALL_PACKED, 'packA', True),
                                         (SYSCALL_UNTERMINATED_PACKED, 'packA', False)):
            with self.subTest(encoding=encoding, terminated=terminated):
                self.assertEqual(self.classify(raw), {
                    'status': 'fresh_fragment', 'encoding': encoding, 'freshness': 'verified',
                    'completeness': 'unknown', 'terminator_present': terminated, 'packed_tail_bytes': 0})
        self.assertEqual(panic.unpack_a(SYSCALL_PACKED).split(b'\0', 1)[0], SYSCALL_REPORT)
        self.assertEqual(panic.unpack_a(SYSCALL_UNTERMINATED_PACKED), SYSCALL_REPORT)

    def test_full_nonce_pid_kind_and_header_are_exact(self):
        changes = ((b'abcdef:123', b'abcdee:123'), (b':123\n', b':124\n'),
                   (b':123\n', b':0123\n'), (b'vz-reboot-panic:', b'vz-force-reset:'),
                   (b'userspace panic: ', b'userspace panic:'),
                   (b':123\n', b':123 suffix\n'), (b':123\n', b':123\x00\n'))
        for before, after in changes:
            with self.subTest(before=before, after=after):
                self.assertEqual(self.classify(SYSCALL_REPORT.replace(before, after))['freshness'], 'unverified')
        for nonce, pid in ((USDT_NONCE[:-1] + 'e', 123), (USDT_NONCE, 124)):
            with self.subTest(nonce=nonce, pid=pid):
                self.assertEqual(panic.classify_syscall(SYSCALL_REPORT, nonce, pid)['freshness'], 'unverified')

    def test_old_classifiers_and_syscall_never_accept_the_other_kind(self):
        for raw in (REPORT, USDT_REPORT, USDT_PACKED):
            with self.subTest(raw=raw):
                self.assertEqual(self.classify(raw)['freshness'], 'unverified')
        for raw in (SYSCALL_REPORT, SYSCALL_PACKED):
            with self.subTest(raw=raw):
                self.assertEqual(panic.classify(raw, USDT_NONCE)['freshness'], 'unverified')
                self.assertEqual(panic.classify_usdt(raw, USDT_NONCE, 123)['freshness'], 'unverified')

    def test_kernel_uuid_and_bounded_first_header_are_required(self):
        cases = ((SYSCALL_HEADER, 'uuid_missing'),
                 (SYSCALL_REPORT[:-1], 'uuid_missing'),
                 (SYSCALL_REPORT.replace(UUID.encode(), b'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'), 'uuid_mismatch'),
                 (b'prefix\n' + SYSCALL_REPORT, 'unrecognized'),
                 (b'\0' + SYSCALL_REPORT, 'unrecognized'),
                 (SYSCALL_REPORT.replace(b'panic(cpu 1', b'panic(cpu -1'), 'truncated'),
                 (b'panic(cpu 1): userspace panic: message copyin failed\nKernel UUID: ' + UUID.encode() + b'\n', 'truncated'))
        for raw, status in cases:
            with self.subTest(status=status, raw=raw):
                self.assertEqual(self.classify(raw)['status'], status)
                self.assertEqual(self.classify(raw)['freshness'], 'unverified')

    def test_duplicate_or_partial_panic_and_uuid_are_ambiguous_even_after_nul(self):
        for suffix in (b'Kernel UUID: broken\n', b'Kernel UUID:',
                       b'Kernel UUID: ' + UUID.encode() + b'\n', SYSCALL_HEADER,
                       b'panic(cpu 2): another panic\n'):
            for separator in (b'', b'\0\n'):
                with self.subTest(suffix=suffix, separator=separator):
                    result = self.classify(SYSCALL_REPORT + separator + suffix)
                    self.assertEqual((result['status'], result['freshness']), ('ambiguous', 'unverified'))

    def test_marker_and_uuid_after_nul_or_in_ignored_packed_tail_do_not_complete_report(self):
        for raw in (b'panic(cpu 1): old panic\0' + SYSCALL_REPORT,
                    SYSCALL_HEADER + b'\0Kernel UUID: ' + UUID.encode() + b'\n',
                    SYSCALL_HEADER[:-1] + b'\0\nKernel UUID: ' + UUID.encode() + b'\n',
                    SYSCALL_PACKED[:-14] + b'ABCDEF'):
            with self.subTest(raw=raw):
                self.assertEqual(self.classify(raw)['freshness'], 'unverified')
        result = self.classify(SYSCALL_PACKED + b'ABCDEF')
        self.assertEqual((result['freshness'], result['packed_tail_bytes']), ('verified', 6))

    def test_raw_and_packa_limits_do_not_upgrade_completeness(self):
        for raw in (SYSCALL_REPORT + b'x' * (panic.MAX_RAW - len(SYSCALL_REPORT)),
                    SYSCALL_PACKED + b'\0' * (panic.MAX_RAW - len(SYSCALL_PACKED))):
            with self.subTest(raw_size=len(raw)):
                result = self.classify(raw)
                self.assertEqual((result['status'], result['completeness']), ('fresh_fragment', 'unknown'))
        for raw, status in ((b'', 'empty'), (b'x' * (panic.MAX_RAW + 1), 'oversized')):
            self.assertEqual(self.classify(raw), {
                'status': status, 'encoding': None, 'freshness': 'unverified', 'completeness': 'unknown',
                'terminator_present': None, 'packed_tail_bytes': 0})
        with self.assertRaises(ValueError): panic.unpack_a(b'\0' * (panic.MAX_RAW + 7))

    def test_nonce_pid_and_raw_types_are_strict(self):
        for nonce in ('bad', 'A' * 64, 'a' * 63, 'a' * 65, USDT_NONCE + '\n',
                      USDT_NONCE + '\0', b'a' * 64, None, True):
            for fn in (panic.syscall_marker, lambda nonce, pid: panic.classify_syscall(SYSCALL_REPORT, nonce, pid)):
                with self.subTest(nonce=nonce), self.assertRaises(ValueError): fn(nonce, 123)
        for pid in (True, 0, -1, 2**31, 1.0, '123', None):
            for fn in (panic.syscall_marker, lambda nonce, pid: panic.classify_syscall(SYSCALL_REPORT, nonce, pid)):
                with self.subTest(pid=pid), self.assertRaises(ValueError): fn(USDT_NONCE, pid)
        for raw in ('not bytes', bytearray(SYSCALL_REPORT), None):
            with self.subTest(raw=raw), self.assertRaises(TypeError): self.classify(raw)




BEGIN_BOOT = b'keepsyms=1 debug=0x102000 vz_ci_nonce=' + NONCE.encode()
BEGIN_HEADER = b'panic(cpu 1 caller 0xffffff8000012345): dtrace: panic action at probe dtrace:::BEGIN (ecb 0xffffff8000001234)\n'
BEGIN_REPORT = BEGIN_HEADER + b'Boot args: ' + BEGIN_BOOT + b'\nKernel UUID: ' + UUID.encode() + b'\n\0'
BEGIN_PACKED = base64.b64decode(
    '8LA7PUaN4XVQDDQOs9llOQiGN5vNZrMZB4PBYDHZjFZL6UBkujw8LutA8LA7PQaFx/T02w0K00Fw+VtcBpHp8vC4rNPphMVj0glC'
    'lcdiEAxvNpvNZjMOBoPBYDHZjJZSCN9vOigsP891oHW5DJ/n2/NeDEQui+vnHgwfg8lgMBjIrv+O01/32z0u98LhcDgcDofD4XA4'
    'HA6Hw+FwOBwOh8PhcDgcDofD4XA4HA6Hw+FwOBwOh8PhcDgcDofD4XA4HA6HFcuy3F1mg6rVJFEHwt1otZkwRmwFY7ZZaxYzBlvC'
    '2UzYghmFNGHxhivaijgFAAAAAAA=')


class BeginPanicData(unittest.TestCase):
    def digest(self, body=BEGIN_BOOT):
        import hashlib
        return hashlib.sha256(body).hexdigest()

    def report(self, body=BEGIN_BOOT, ending=b'\n'):
        return BEGIN_HEADER + b'Boot args: ' + body + ending + b'Kernel UUID: ' + UUID.encode() + b'\n\0'

    def test_same_panic_bootargs_proves_freshness(self):
        self.assertEqual(panic.classify_begin(BEGIN_REPORT,NONCE,self.digest()),
                         {'status':'fresh_fragment','encoding':'raw','freshness':'verified','completeness':'unknown',
                          'terminator_present':True,'packed_tail_bytes':0})
        self.assertEqual(panic.classify_begin(BEGIN_REPORT[:-1],NONCE,self.digest())['freshness'],'verified')
        self.assertEqual(panic.classify_begin(self.report(ending=b'\r\n'),NONCE,self.digest())['freshness'],'verified')

    def test_literal_packed_report_and_tail(self):
        result=panic.classify_begin(BEGIN_PACKED,NONCE,self.digest())
        self.assertEqual((result['status'],result['encoding'],result['completeness']),('fresh_fragment','packA','unknown'))
        result=panic.classify_begin(BEGIN_PACKED+b'xyz',NONCE,self.digest())
        self.assertEqual((result['freshness'],result['packed_tail_bytes']),('verified',3))

    def test_nonce_hash_uuid_and_header_are_all_required(self):
        self.assertEqual(panic.classify_begin(BEGIN_REPORT,'b'*64,self.digest())['freshness'],'unverified')
        self.assertEqual(panic.classify_begin(BEGIN_REPORT,NONCE,'c'*64)['freshness'],'unverified')
        for raw in (BEGIN_REPORT.replace(UUID.encode(),b'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'),
                    BEGIN_REPORT.replace(b'dtrace:::BEGIN',b'dtrace:::END'),
                    BEGIN_HEADER+b'Kernel UUID: '+UUID.encode()+b'\n\0'):
            with self.subTest(raw=raw):self.assertEqual(panic.classify_begin(raw,NONCE,self.digest())['freshness'],'unverified')
        changed=BEGIN_BOOT.replace(b'keepsyms=1',b'keepsyms=2')
        self.assertEqual(panic.classify_begin(self.report(changed),NONCE,self.digest())['freshness'],'unverified')

    def test_full_token_ascii_and_255_byte_bound(self):
        body=b'x'*(254-len(BEGIN_BOOT))+b' '+BEGIN_BOOT
        self.assertEqual(len(body),255)
        self.assertEqual(panic.classify_begin(self.report(body),NONCE,self.digest(body))['freshness'],'verified')
        bodies=(b'x'+body,BEGIN_BOOT.replace(b'vz_ci_nonce=',b'-vz_ci_nonce='),
                BEGIN_BOOT+b' vz_ci_nonce='+NONCE.encode(),BEGIN_BOOT+b'x',
                BEGIN_BOOT.replace(b'keepsyms=1',b'keepsyms=\t1'),BEGIN_BOOT+b'\x80')
        for invalid in bodies:
            with self.subTest(body=invalid):self.assertEqual(panic.classify_begin(self.report(invalid),NONCE,self.digest(invalid))['freshness'],'unverified')
        self.assertEqual(panic.classify_begin(self.report(ending=b''),NONCE,self.digest())['freshness'],'unverified')

    def test_duplicate_and_after_nul_lines_do_not_supply_freshness(self):
        raws=(BEGIN_REPORT[:-1]+b'Boot args: '+BEGIN_BOOT+b'\n\0',
              BEGIN_REPORT+b'Boot args: '+BEGIN_BOOT+b'\n',
              BEGIN_HEADER+b'Kernel UUID: '+UUID.encode()+b'\n\0Boot args: '+BEGIN_BOOT+b'\n',
              BEGIN_REPORT+BEGIN_REPORT,
              BEGIN_REPORT[:-1]+b'Kernel UUID: '+UUID.encode()+b'\n\0')
        for raw in raws:
            with self.subTest(raw=raw):self.assertEqual(panic.classify_begin(raw,NONCE,self.digest())['freshness'],'unverified')

    def test_every_required_prefix_cut_is_unverified(self):
        for end in range(len(BEGIN_REPORT)-1):
            with self.subTest(end=end):self.assertEqual(panic.classify_begin(BEGIN_REPORT[:end],NONCE,self.digest())['freshness'],'unverified')

    def test_argument_types_and_limits_are_closed(self):
        for nonce,digest in ((None,self.digest()),('A'*64,self.digest()),(NONCE,None),(NONCE,'g'*64)):
            with self.subTest(nonce=nonce,digest=digest),self.assertRaises(ValueError):panic.classify_begin(BEGIN_REPORT,nonce,digest)
        with self.assertRaises(TypeError):panic.classify_begin('not bytes',NONCE,self.digest())
        self.assertEqual(panic.classify_begin(b'',NONCE,self.digest())['status'],'empty')
        self.assertEqual(panic.classify_begin(b'x'*(panic.MAX_RAW+1),NONCE,self.digest())['status'],'oversized')

    def test_old_classifiers_do_not_accept_begin(self):
        self.assertEqual(panic.classify(BEGIN_REPORT,NONCE)['freshness'],'unverified')
        self.assertEqual(panic.classify_usdt(BEGIN_REPORT,NONCE,123)['freshness'],'unverified')
        self.assertEqual(panic.classify_syscall(BEGIN_REPORT,NONCE,123)['freshness'],'unverified')


if __name__ == '__main__': unittest.main()
