import copy
import dataclasses
import hashlib
import unittest

import kdp_crashdump as wire
import recovery_netdump_capture as capture
import recovery_nvram_panic as panic


class Capture(unittest.TestCase):
    NONCE = 'a' * 64
    NAME = 'fragment'

    def prime(self):
        return {'binding': '123/1/' + 'b' * 40, 'nonce': self.NONCE,
                'baseline_boot_uuid': 'AAAAAAAA-1111-1111-1111-111111111111',
                'boot_uuid': 'BBBBBBBB-2222-2222-2222-222222222222',
                'core_identity': 'c' * 64, 'cert_fingerprint': 'd' * 64, 'recovery_check_id': 9}

    def trigger(self):
        prime = self.prime()
        return {'scope': {'binding': prime['binding'], 'nonce': prime['nonce'], 'baseline': prime['baseline_boot_uuid'],
                          'source_identity': prime['core_identity'], 'debug_boot_uuid': prime['boot_uuid']},
                'helper_sha256': 'e' * 64, 'helper_pid': 41, 'tracer_pid': 42, 'ready': True}

    def scope(self):
        return capture.CaptureScope.from_trigger(self.prime(), 'f' * 64, self.trigger())

    def body(self, *, nonce=None, pid=41, uuid=None):
        return ('panic(cpu 0 caller 0x1234): dtrace: panic action at probe pid' + str(pid) +
                ':helper:vz_nonce_' + (self.NONCE if nonce is None else nonce) + ':entry (ecb 0xabcd)\nKernel UUID: ' +
                (panic.KERNEL_UUID if uuid is None else uuid) + '\n').encode()

    def stream(self, body=None, *, eof=False, prefix=b'panic('):
        stream = capture.FragmentStream(self.NAME, required_prefix=prefix)
        self.assertEqual(wire.decode_ack(stream.receive(wire.encode_wrq(self.NAME))), 0)
        if body is not None:
            for index, start in enumerate(range(0, len(body), 512), 1):
                packet = wire.encode_paniclog_data(index, body[start:start + 512], self.NAME, b'Y' * (len(self.NAME) + 1))
                self.assertEqual(wire.decode_ack(stream.receive(packet)), index)
            if eof: self.assertIsNone(stream.receive(wire.encode_eof((len(body) + 511) // 512 + 1)))
        return stream

    def test_flat_scope_is_immutable_and_bound_to_actual_ready_trigger(self):
        scope = self.scope()
        self.assertEqual(capture.CaptureScope.from_record(scope.record()), scope)
        self.assertEqual(set(scope.record()), set(self.prime()) | {'intent_sha256', 'helper_sha256', 'helper_pid', 'tracer_pid'})
        with self.assertRaises(dataclasses.FrozenInstanceError): scope.helper_pid = 2
        for key, value in (('helper_pid', True), ('helper_pid', 0), ('helper_pid', 2**31),
                           ('tracer_pid', 41), ('core_identity', '0' * 64), ('nonce', 'bad'),
                           ('boot_uuid', self.prime()['baseline_boot_uuid'])):
            record = scope.record(); record[key] = value
            if key == 'core_identity':
                self.assertNotEqual(capture.CaptureScope.from_record(record), scope)
            else:
                with self.subTest(key=key), self.assertRaises(ValueError): capture.CaptureScope.from_record(record)
        for key, value in (('ready', False), ('helper_pid', True), ('helper_sha256', 'bad'), ('tracer_pid', 41)):
            trigger = {**self.trigger(), key: value}
            with self.assertRaises(ValueError): capture.CaptureScope.from_trigger(self.prime(), 'f' * 64, trigger)
        for key in self.trigger()['scope']:
            trigger = copy.deepcopy(self.trigger()); trigger['scope'][key] = 'foreign'
            with self.subTest(key=key), self.assertRaises(ValueError): capture.CaptureScope.from_trigger(self.prime(), 'f' * 64, trigger)
        with self.assertRaises(ValueError): capture.CaptureScope.from_record({**scope.record(), 'raw': 'forbidden'})
        with self.assertRaises(ValueError): capture.CaptureScope.from_trigger({**self.prime(), 'extra': True}, 'f' * 64, self.trigger())

    def test_only_correct_nonce_uuid_and_helper_pid_produce_fresh_fragment(self):
        result = capture.classify_kernel_fragment(self.body(), self.NONCE, 41)
        self.assertEqual((result['status'], result['freshness'], result['completeness'], result['pid_matches']),
                         ('fresh_fragment', 'verified', 'unknown', True))
        for body, expected in ((self.body(nonce='0' * 64), 'nonce_missing'), (self.body(pid=43), 'pid_mismatch'),
                               (self.body(uuid='AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'), 'uuid_mismatch'),
                               (self.body() + b'Kernel UUID: ' + panic.KERNEL_UUID.encode() + b'\n', 'ambiguous'),
                               (self.body() + self.body(), 'ambiguous'), (b'panic(cpu 0', 'truncated'),
                               (self.body().rstrip(b'\n'), 'uuid_missing'), (b'X' * 200, 'unrecognized')):
            with self.subTest(expected=expected):
                classified = capture.classify_kernel_fragment(body, self.NONCE, 41)
                self.assertEqual(classified['status'], expected)
                self.assertEqual(classified['freshness'], 'unverified')
                self.assertEqual(classified['completeness'], 'unknown')
        with self.assertRaises(ValueError): capture.classify_kernel_fragment(self.body(), self.NONCE, True)

    def test_raw_classifier_never_attempts_packed_candidates(self):
        body = self.body()
        body += b' ' * (-len(body) % 8)
        packed = b''.join(sum(byte << (7 * index) for index, byte in enumerate(body[start:start + 8])).to_bytes(7, 'little')
                          for start in range(0, len(body), 8))
        self.assertNotEqual(capture.classify_kernel_fragment(packed, self.NONCE, 41)['freshness'], 'verified')

    def test_eof_ack_is_pending_until_owner_saves_and_only_same_eof_reoffers_it(self):
        stream = self.stream(self.body())
        eof = wire.encode_eof(2)
        self.assertIsNone(stream.receive(eof))
        self.assertEqual(stream.pending_eof_ack, b'\x00\x04\x00\x00\x00\x02')
        self.assertTrue(stream.eof_accepted)
        self.assertIsNone(stream.receive(wire.encode_eof(3)))
        self.assertIsNone(stream.pending_eof_ack)
        self.assertIsNone(stream.receive(eof))
        self.assertEqual(wire.decode_ack(stream.pending_eof_ack), 2)
        stream.finish('deadline')
        self.assertEqual(stream.termination, 'eof')
        result = capture.kernel_result(self.scope(), stream)
        self.assertEqual(result['status'], 'fresh_fragment')
        self.assertEqual(result['completeness'], 'unknown')
        self.assertEqual(capture.validate_result(result, self.scope()), result)
        self.assertNotIn('panic(cpu', str(result))

    def test_full_short_and_trailing_y_data_are_preserved_but_wire_tails_are_discarded(self):
        body = self.body() + b'Y' * (512 - len(self.body())) + b'lastY'
        stream = self.stream(body, eof=True)
        self.assertEqual(stream.data, body)
        self.assertEqual(stream.public_fact()['body_sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(stream.forensic, b'')

    def test_uuid_present_only_in_wire_tail_cannot_make_fragment_fresh(self):
        filename = 'f' * 16
        body = self.body().rstrip(b'\n')[:-10]
        trailer = panic.KERNEL_UUID[-10:].encode() + b'\n' + b'Y' * 6
        stream = capture.FragmentStream(filename)
        stream.receive(wire.encode_wrq(filename))
        stream.receive(wire.encode_paniclog_data(1, body, filename, trailer))
        stream.finish('idle')
        self.assertEqual(stream.data, body)
        self.assertEqual(capture.kernel_result(self.scope(), stream)['freshness'], 'unverified')

    def test_nonce_and_uuid_existing_only_in_tail_are_not_classified(self):
        filename = 'f' * 200
        body, rest = self.body().split(b'vz_nonce_', 1)
        body += b'vz_nonce_'
        trailer = rest + b'Y' * (201 - len(rest))
        stream = capture.FragmentStream(filename)
        stream.receive(wire.encode_wrq(filename))
        stream.receive(wire.encode_paniclog_data(1, body, filename, trailer))
        stream.finish('deadline')
        self.assertEqual(stream.data, body)
        self.assertEqual(capture.kernel_result(self.scope(), stream)['classification']['status'], 'truncated')

    def test_empty_eof_and_unreceived_future_block_do_not_create_fresh_data(self):
        for eof in (False, True):
            stream = self.stream()
            if eof:
                self.assertIsNone(stream.receive(wire.encode_eof(1)))
                self.assertEqual(stream.termination, 'invalid')
            else:
                packet = wire.encode_paniclog_data(2, self.body(), self.NAME, b'Y' * (len(self.NAME) + 1))
                self.assertIsNone(stream.receive(packet))
                stream.finish('idle')
            result = capture.kernel_result(self.scope(), stream)
            self.assertEqual((result['status'], result['byte_count'], result['eof_accepted']), ('unverified', 0, False))
            self.assertEqual(result['classification']['status'], 'empty')

    def test_huge_header_pid_is_unverified_without_integer_conversion(self):
        body = self.body().replace(b'probe pid41:', b'probe pid' + b'9' * 5000 + b':')
        classified = capture.classify_kernel_fragment(body, self.NONCE, 41)
        self.assertEqual((classified['status'], classified['pid_matches']), ('pid_mismatch', False))

    def test_duplicate_data_ignores_stale_tail_but_conflict_keeps_first_prefix(self):
        stream = self.stream(self.body())
        duplicate = wire.encode_paniclog_data(1, self.body(), self.NAME, b'X' * (len(self.NAME) + 1))
        self.assertEqual(wire.decode_ack(stream.receive(duplicate)), 1)
        conflict = wire.encode_paniclog_data(1, self.body() + b'x', self.NAME, b'Y' * (len(self.NAME) + 1))
        self.assertIsNone(stream.receive(conflict))
        self.assertEqual(stream.data, self.body())
        self.assertEqual(stream.forensic, conflict)
        self.assertEqual(stream.termination, 'invalid')
        self.assertEqual(capture.kernel_result(self.scope(), stream)['status'], 'fresh_fragment')

    def test_invalid_and_size_limit_keep_prefix_and_bounded_first_forensic(self):
        stream = self.stream(self.body())
        invalid = b'\x00\x06' + b'X' * 8000
        stream.receive(invalid)
        self.assertEqual(stream.forensic, invalid[:4096])
        stream.receive(b'\x00\x08second')
        self.assertEqual(stream.forensic, invalid[:4096])
        self.assertEqual(stream.data, self.body())
        body = self.body() + b'X' * (12288 - len(self.body()))
        stream = self.stream(body)
        stream.receive(wire.encode_paniclog_data(25, b'overflow', self.NAME, b'Y' * (len(self.NAME) + 1)))
        self.assertEqual(stream.termination, 'limit')
        self.assertEqual(len(stream.data), 12288)
        self.assertIsNone(stream.pending_eof_ack)
        self.assertIsNone(stream.receive(wire.encode_eof(25)))
        self.assertEqual(capture.kernel_result(self.scope(), stream)['completeness'], 'unknown')

    def test_idle_deadline_and_synthetic_stream_never_claim_kernel_freshness(self):
        for reason in ('idle', 'deadline'):
            stream = self.stream(self.body()); stream.finish(reason)
            self.assertEqual(capture.kernel_result(self.scope(), stream)['termination'], reason)
            self.assertEqual(capture.kernel_result(self.scope(), stream)['status'], 'fresh_fragment')
        stream = self.stream(b'VZ_SYNTHETIC_NON_KERNEL\nfixture', eof=True, prefix=b'VZ_SYNTHETIC_NON_KERNEL\n')
        self.assertEqual(stream.data, b'VZ_SYNTHETIC_NON_KERNEL\nfixture')
        self.assertEqual(stream.public_fact()['termination'], 'eof')
        self.assertIsNone(stream.receive(wire.encode_eof(2)))
        self.assertEqual(capture.kernel_result(self.scope(), stream)['status'], 'unverified')

    def test_external_limit_keeps_empty_or_fresh_partial_body_consistent(self):
        for body, expected in ((None, 'unverified'), (self.body(), 'fresh_fragment')):
            with self.subTest(status=expected):
                stream = self.stream(body)
                stream.finish('limit')
                result = capture.kernel_result(self.scope(), stream)
                self.assertEqual(result['termination'], 'limit')
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['byte_count'], len(body) if body is not None else 0)
                self.assertEqual(result['completeness'], 'unknown')
                self.assertFalse(result['eof_accepted'])
                self.assertIsNone(stream.pending_eof_ack)
                self.assertEqual(capture.validate_result(result, self.scope()), result)
                stream.finish('deadline')
                self.assertEqual(stream.termination, 'limit')

    def test_armed_and_result_boundaries_reject_foreign_scope_peer_and_boolean_counts(self):
        scope = self.scope()
        expected = {'prime_proof_sha256': '1' * 64, 'offer_digest': '2' * 64,
                    'peer': {'ip': '8.8.8.8', 'port': 40000}, 'receiver_check_id': 10}
        armed = capture.make_armed(scope, **expected)
        self.assertEqual(capture.validate_armed(armed, scope, **expected), armed)
        for key, value in (('prime_proof_sha256', '0' * 64), ('offer_digest', '0' * 64),
                           ('peer', {'ip': '8.8.8.8', 'port': True}), ('receiver_check_id', True)):
            with self.subTest(key=key), self.assertRaises(ValueError): capture.validate_armed({**armed, key: value}, scope, **expected)
        for key in ('nonce', 'core_identity', 'intent_sha256', 'helper_sha256'):
            bad = copy.deepcopy(armed); bad['scope'][key] = '0' * 64
            with self.assertRaises(ValueError): capture.validate_armed(bad, scope, **expected)
        stream = self.stream(self.body(), eof=True)
        result = capture.kernel_result(scope, stream)
        for key, value in (('byte_count', True), ('body_sha256', 'bad'), ('completeness', 'complete'),
                           ('termination', 'unknown'), ('eof_accepted', False), ('raw', 'forbidden')):
            with self.subTest(key=key), self.assertRaises(ValueError): capture.validate_result({**result, key: value}, scope)
        bad = copy.deepcopy(result); bad['classification']['pid_matches'] = False
        with self.assertRaises(ValueError): capture.validate_result(bad, scope)
        for key, value in (('helper_pid', 43), ('tracer_pid', 44), ('intent_sha256', '0' * 64),
                           ('boot_uuid', 'CCCCCCCC-3333-3333-3333-333333333333')):
            bad = copy.deepcopy(result); bad['scope'][key] = value
            with self.subTest(scope_key=key), self.assertRaises(ValueError): capture.validate_result(bad, scope)

    def test_result_rejects_impossible_unverified_classification_combinations(self):
        scope = self.scope()
        result = capture.kernel_result(scope, self.stream(self.body(), eof=True))
        for status in ('pid_mismatch', 'empty', 'oversized', 'truncated', 'unrecognized'):
            bad = copy.deepcopy(result)
            bad.update(status='unverified', freshness='unverified')
            bad['classification'].update(status=status, freshness='unverified')
            if status in ('empty', 'oversized'):
                bad['classification'].update(encoding=None, terminator_present=None, pid_matches=None)
            with self.subTest(status=status), self.assertRaises(ValueError): capture.validate_result(bad, scope)

    def test_stream_state_cannot_be_changed_by_the_io_owner(self):
        stream = capture.FragmentStream(self.NAME)
        for key, value in (('termination', 'eof'), ('eof_accepted', True), ('pending_eof_ack', b'fake')):
            with self.subTest(key=key), self.assertRaises(AttributeError): setattr(stream, key, value)


if __name__ == '__main__': unittest.main()
