import copy
import errno
import socket
import sys
import threading
import unittest

import udp_connection_control as c


class Control(unittest.TestCase):
    def bases(self):
        ctx = {'run': '123', 'attempt': '1', 'sha': 'a' * 40, 'role': 'intel', 'port_mode': 'kernel-source'}
        sources = {key: 'b' * 64 for key in c.SOURCE_KEYS}
        host = c.make_base(ctx, sources, {'ip': '8.8.8.8', 'port': 30000}, 40000, 'c' * 64)
        receiver = c.make_base({**ctx, 'role': 'receiver'}, sources, {'ip': '1.1.1.1', 'port': 40000}, 35000, 'd' * 64)
        return host, receiver

    def record(self):
        host, receiver = self.bases()
        return {'base': host, 'peer': {'check_id': 10, 'base': receiver}, 'phase': 'offer', 'history': [], 'failure': None}

    def test_round_history_rejects_replacement_rewind_and_skip(self):
        offer = self.record()
        ready = c.ready_record(offer, 0)
        c.validate_transition(offer, ready)
        done = c.done_record(ready, c.not_started())
        c.validate_transition(ready, done)
        following = c.ready_record(done, 1)
        c.validate_transition(done, following)
        for changed in (offer, {**ready, 'base': {**ready['base'], 'nonce': 'e' * 64}},
                        {**ready, 'peer': {**ready['peer'], 'check_id': 11}}):
            with self.assertRaises(ValueError): c.validate_transition(done, changed)
        changed = copy.deepcopy(done)
        changed['history'][0]['scope_sha256'] = '0' * 64
        with self.assertRaises(ValueError): c.validate_transition(ready, changed)
        with self.assertRaises(ValueError): c.ready_record(offer, 1)
        self.assertEqual(c.start_decision(ready, 0), 'run')
        self.assertEqual(c.start_decision(done, 0), 'not_started_peer_done')
        self.assertEqual(c.start_decision(following, 0), 'not_started_peer_done')
        self.assertEqual(done['history'][0]['result']['overlap'], 'overlap_unverified')

    def test_ready_to_next_ready_accepts_missed_done_but_preserves_confirmed_prefix(self):
        offer = self.record()
        ready0 = c.ready_record(offer, 0)
        done0 = c.done_record(ready0, c.not_started())
        ready1 = c.ready_record(done0, 1)
        self.assertEqual(c.validate_transition(ready0, ready1), ready1)
        changed = copy.deepcopy(ready1)
        changed['history'][0]['result'] = {**c.not_started(), 'overlap': 'matching_packets_observed'}
        with self.assertRaises(ValueError): c.validate_transition(done0, changed)
        done1 = c.done_record(ready1, c.not_started())
        ready2 = c.ready_record(done1, 2)
        with self.assertRaises(ValueError): c.validate_transition(ready0, ready2)

    def test_completed_control_result_reaches_public_projection(self):
        record = self.record()
        for index in range(3):
            record = c.done_record(c.ready_record(record, index), c.not_started())
        record = {**record, 'phase': 'complete'}
        result = c.control_result('completed', 'not_required', record)
        public = c.public_projection(result)
        self.assertEqual(result['evidence'], None)
        self.assertEqual(public['status'], 'completed')
        self.assertEqual(public['record_sha256'], c.n.digest(record))
        self.assertEqual(len(public['history']), 3)
        self.assertIsNone(public['evidence'])

    def test_public_projection_omits_addresses_and_has_explicit_non_kernel_scope(self):
        record = self.record()
        projected = c.public_projection({'status': 'failed', 'cleanup': 'not_created', 'record': record, 'evidence': None})
        self.assertEqual(projected['scope'], 'userspace_non_kernel')
        self.assertEqual(projected['clock_scope'], 'local_unsynchronized')
        self.assertEqual(projected['record_sha256'], c.n.digest(record))
        self.assertEqual(projected['peer_check_id'], 10)
        self.assertEqual(projected['sources'], record['base']['sources'])
        public = c.n.canonical(projected)
        for address in ('8.8.8.8', '1.1.1.1'):
            self.assertNotIn(address, public)
        self.assertNotIn('record', projected)
        with self.assertRaises(ValueError): c.public_projection({'status': 'failed', 'cleanup': 'not_created', 'record': record, 'evidence': None, 'raw': 'private'})

    def test_check_readback_mismatch_produces_safe_field_evidence(self):
        ctx = {'run': '123', 'attempt': '1', 'sha': 'a' * 40, 'role': 'intel', 'port_mode': 'kernel-source'}
        name, external = c.attributes(ctx, 'intel')
        check = {'id': 9, 'name': name, 'external_id': external, 'head_sha': ctx['sha'],
                 'app': {'id': 15368, 'slug': 'github-actions'},
                 'details_url': 'https://github.com/Code-Hex/vz-ci-test/runs/9', 'status': 'completed', 'conclusion': 'neutral',
                 'output': {'title': 'Userspace UDP connection control', 'summary': 'private-summary', 'text': ''}}
        with self.assertRaises(c.n.EvidenceFailure) as caught:
            c.verify_check(check, ctx, 'intel', 'get_readback', expected_id=9, expected_summary='different-private')
        fact = caught.exception.fact
        self.assertEqual(fact['stage'], 'get_readback')
        self.assertFalse(fact['matches']['summary'])
        self.assertTrue(fact['matches']['status'])
        self.assertNotIn('private', c.n.canonical(fact))
        with self.assertRaises(c.n.EvidenceFailure) as post:
            c.check_identity({**check, 'head_sha': 'b' * 40}, ctx, 'intel')
        self.assertFalse(post.exception.fact['matches']['head_sha'])

    def test_workflow_pin_and_observed_timing_are_required_and_typed(self):
        self.assertIn('workflow_sha256', c.SOURCE_KEYS)
        self.assertEqual(c.sources()['workflow_sha256'], c.hashlib.sha256((c.Path(c.__file__).resolve().parents[1] / '.github/workflows/udp-connection-control.yml').read_bytes()).hexdigest())
        result = {'status': 'observed', 'overlap': 'overlap_unverified', 'adapter_connected': False,
                  'exchange': {'hello_received': False, 'ack_received': False, 'sent': 40, 'valid_peer_port_mismatches': 0, 'other_peer_port_count': 0},
                  'counters': c.empty_counts(), 'timing': {'monotonic_start': 100.0, 'monotonic_end': 120.0, 'unix_start': 1800000000.0, 'unix_end': 1800000020.0}}
        self.assertEqual(c.validate_result(result, 'receiver', 0), result)
        for change in ({'monotonic_start': True}, {'monotonic_end': 99.0}, {'unix_end': float('nan')}, {'unix_end': 2 ** 1000}):
            with self.assertRaises(ValueError): c.validate_result({**result, 'timing': {**result['timing'], **change}}, 'receiver', 0)
        self.assertIsNone(c.not_started()['timing'])

    def test_round_nonce_is_shared_and_changes_for_every_treatment(self):
        host, receiver = self.bases()
        a = c.round_scope(host, receiver, 0)
        b = c.round_scope(receiver, host, 0)
        self.assertEqual(a, b)
        self.assertNotEqual(c.packet_nonce(a, 'intel'), c.packet_nonce(a, 'receiver'))
        self.assertNotEqual(c.packet_nonce(a, 'intel'), c.packet_nonce(c.round_scope(host, receiver, 2), 'intel'))
        self.assertEqual([c.MODES[i] for i in range(3)], ['unconnected', 'connected', 'unconnected'])

    def test_native_adapter_observes_without_changing_packets_or_ack_rules(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as host, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            for sock in (host, peer, other): sock.bind(('127.0.0.1', 0))
            adapter = c.Observer(host, peer.getsockname(), b'a' * 16, b'b' * 16, connected=False)
            packets = [b'bad', c.u.PACKET.pack(b'KDP1', 1, b'b' * 16, b'a' * 16, 7),
                       c.u.PACKET.pack(b'KDP1', 2, b'b' * 16, b'a' * 16, 7)]
            for packet in packets:
                other.sendto(packet, host.getsockname())
                self.assertEqual(adapter.recvfrom(1024), (packet, other.getsockname()))
            self.assertEqual(adapter.counts['length_invalid'], 1)
            self.assertEqual(adapter.counts['valid_nonce_same_ip_other_port'], 1)
            self.assertEqual(adapter.counts['sequence_invalid'], 1)
            adapter.sendto(c.u.PACKET.pack(b'KDP1', 2, b'a' * 16, b'b' * 16, 7), peer.getsockname())
            self.assertEqual(adapter.sent_sequences, set())
            adapter.sendto(c.u.PACKET.pack(b'KDP1', 1, b'a' * 16, b'b' * 16, 7), peer.getsockname())
            self.assertEqual(adapter.sent_sequences, {7})
            other.sendto(packets[-1], host.getsockname())
            adapter.recvfrom(1024)
            self.assertEqual(adapter.counts['valid_nonce_same_ip_other_port'], 2)
            self.assertNotIn('127.0.0.1', c.n.canonical(adapter.fact()))

    def test_native_failed_send_and_foreign_ip_observation_keep_acceptance_rules(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        observer = c.Observer(sock, ('127.0.0.1', 9), b'a' * 16, b'b' * 16, connected=False)
        sock.close()
        with self.assertRaises(OSError):
            observer.sendto(c.u.PACKET.pack(b'KDP1', 1, b'a' * 16, b'b' * 16, 1), observer.peer)
        self.assertEqual(observer.sent_sequences, set())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(('127.0.0.1', 0)); sender.bind(('127.0.0.1', 0))
            receiver.settimeout(1)
            observer = c.Observer(receiver, ('8.8.8.8', sender.getsockname()[1]), b'a' * 16, b'b' * 16, connected=False)
            packet = c.u.PACKET.pack(b'KDP1', 1, b'b' * 16, b'a' * 16, 999)
            sender.sendto(packet, receiver.getsockname())
            self.assertEqual(observer.recvfrom(1024)[0], packet)
            self.assertEqual(observer.fact()['valid_nonce_other_ip'], 1)
            self.assertEqual(observer.fact()['sequence_invalid'], 0)

    def test_receiver_adapter_stays_unconnected_for_connected_treatment(self):
        result = {'status': 'observed', 'overlap': 'overlap_unverified', 'adapter_connected': False,
                  'exchange': {'hello_received': False, 'ack_received': False, 'sent': 40,
                               'valid_peer_port_mismatches': 0, 'other_peer_port_count': 0}, 'counters': c.empty_counts(),
                  'timing': {'monotonic_start': 100.0, 'monotonic_end': 120.0, 'unix_start': 1800000000.0, 'unix_end': 1800000020.0}}
        self.assertEqual(c.validate_result(result, 'receiver', 1), result)
        with self.assertRaises(ValueError): c.validate_result(result, 'intel', 1)
        with self.assertRaises(ValueError): c.validate_result({**result, 'overlap': 'matching_packets_observed'}, 'receiver', 1)

    def test_native_exchange_still_uses_exact_peer_hello_and_ack(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(('127.0.0.1', 0)); b.bind(('127.0.0.1', 0))
            a.connect(b.getsockname())
            host = c.Observer(a, b.getsockname(), b'a' * 16, b'b' * 16, connected=True)
            receiver = c.Observer(b, a.getsockname(), b'b' * 16, b'a' * 16, connected=False)
            facts = []
            thread = threading.Thread(target=lambda: facts.append(c.u.exchange(receiver, a.getsockname(), b'b' * 16, b'a' * 16, .2)))
            thread.start()
            facts.append(c.u.exchange(host, b.getsockname(), b'a' * 16, b'b' * 16, .2))
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertTrue(all(fact['hello_received'] and fact['ack_received'] for fact in facts))
            self.assertTrue(host.fact()['total'] > 0)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin disconnectx ABI')
    def test_native_disconnect_is_reversible_on_same_owned_fd_and_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            for sock in (a, b, other): sock.bind(('127.0.0.1', 0)); sock.settimeout(.2)
            fd, port = a.fileno(), a.getsockname()[1]
            a.sendto(b'A1', b.getsockname()); self.assertEqual(b.recvfrom(20)[0], b'A1')
            a.connect(b.getsockname()); a.send(b'B'); self.assertEqual(b.recvfrom(20)[0], b'B')
            other.sendto(b'filtered', a.getsockname())
            with self.assertRaises(socket.timeout): a.recvfrom(20)
            c.disconnect_owned_udp(a)
            self.assertEqual((a.fileno(), a.getsockname()[1]), (fd, port))
            with self.assertRaises(OSError) as caught: a.getpeername()
            self.assertEqual(caught.exception.errno, errno.ENOTCONN)
            a.sendto(b'A2', b.getsockname()); self.assertEqual(b.recvfrom(20)[0], b'A2')
            other.sendto(b'accepted', ('127.0.0.1', port)); self.assertEqual(a.recvfrom(20)[0], b'accepted')

    def test_public_schema_rejects_private_fields_and_bool_counts(self):
        record = self.record()
        c.validate_record(record)
        for changed in ({**record, 'raw': 'private'}, {**record, 'base': {**record['base'], 'local_port': True}},
                        {**record, 'base': {**record['base'], 'endpoint': {'ip': '192.168.1.1', 'port': 40000}}}):
            with self.assertRaises(ValueError): c.validate_record(changed)
        for changed in ({**c.empty_counts(), 'total': True}, {**c.empty_counts(), 'raw': 1}):
            with self.assertRaises(ValueError): c.validate_counts(changed)


if __name__ == '__main__': unittest.main()
