import copy
import dataclasses
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

import recovery_netdump as n
from recovery_netdump_settings import NetdumpSettings


class Discovery(unittest.TestCase):
    def test_waiting_mapping_rejects_a_primary_change_even_if_it_returns(self):
        expected = n.Endpoint('8.8.8.8', 40000)
        primary = {'server_ip': '1.1.1.1', 'state': 'observed', 'ip': expected.ip, 'port': expected.port}
        secondary = {'server_ip': '1.0.0.1', 'state': 'observed', 'ip': expected.ip, 'port': 40001}
        self.assertEqual(n.mapping_result((expected.ip, expected.port), [primary, secondary, primary], expected), expected)
        changed = {**primary, 'port': 40002}
        with self.assertRaises(ValueError):
            n.mapping_result((expected.ip, expected.port), [changed, secondary, primary], expected)
        with self.assertRaises(ValueError):
            n.mapping_result((expected.ip, 40002), [primary, secondary, changed], expected)

    B1 = 'AAAAAAAA-1111-1111-1111-111111111111'
    B2 = 'BBBBBBBB-2222-2222-2222-222222222222'

    def baseline(self):
        return n.BootBaseline.from_profile(self.B1, {'status': 'observed', 'debug_mask': None,
            'nondebug_token_count': 0, 'nondebug_sha256': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'})

    def prime_plan(self):
        return dataclasses.replace(self.plan(), offer=dataclasses.replace(self.offer(), purpose='prime'), baseline=self.baseline())

    def prime_scope(self):
        plan = self.prime_plan()
        return n.PrimeScope(plan.offer.binding, plan.nonce, self.B1, self.B2,
                            plan.offer.core_identity, plan.offer.cert_fingerprint, 9)

    def core_check(self):
        plan, scope = self.prime_plan(), self.prime_scope()
        remaining = {**plan.baseline.profile(), 'debug_mask': 0x22040}
        control = {'status': 'observed', 'settings_sha256': plan.settings.digest(),
                   'remaining_profile': remaining, 'full_profile': {**remaining, 'nondebug_token_count': 4, 'nondebug_sha256': '1' * 64}}
        facts = {'current_boot_uuid': self.B2, 'active_debug_mask': 0x22040, 'active_bootargs_status': 'observed_debug',
                 'bootplist_restored': True, 'bootplist_restore': {key: {'bytes': True, 'metadata': True, 'timestamps': True} for key in ('data', 'preboot')},
                 'bootplist_file_states': {'data': 'staged', 'preboot': 'original'}, 'netdump_active_control': control,
                 'owner_events': [{'event': event, 'source_identity': scope.core_identity, 'actual_boot_uuid': self.B1} for event in ('staged', 'bootplist_staged', 'intent')]}
        facts['owner_events'][1]['bootplist_stage'] = {'data': 'staged', 'preboot': 'staged', 'metadata_preserved': True}
        summary = {'protocol': 'vz-recovery-v1', 'phase': 'boot_core', 'binding': scope.binding, 'nonce': scope.nonce,
                   'baseline_boot_uuid': self.B1, 'current_boot_uuid': self.B2, 'trigger': 'reboot-quick',
                   'cert_fingerprint': scope.cert_fingerprint, 'debug_boot': True, 'debug_source': 'bootplist',
                   'after_debug_boot': 'netdump-prime', 'debug_boot_facts': facts}
        return {'id': 9, 'name': 'Runner recovery 123', 'head_sha': 'a' * 40, 'external_id': scope.binding,
                'app': {'id': 15368, 'slug': 'github-actions'}, 'details_url': 'https://github.com/Code-Hex/vz-ci-test/runs/9',
                'status': 'in_progress', 'conclusion': None, 'output': {'title': 'Boot core recovered', 'summary': json.dumps(summary), 'text': ''}}

    def test_root_core_snapshot_requires_actual_owned_restored_active_same_capture_fact(self):
        scope, plan = self.prime_scope(), self.prime_plan()
        check = self.core_check()
        snapshot = n.core_snapshot(check, scope, plan.public_fact())
        self.assertEqual(snapshot['check_id'], 9)
        self.assertEqual(snapshot['facts']['netdump_active_control']['settings_sha256'], plan.settings.digest())
        for path, bad in ((('current_boot_uuid',), self.B1), (('nonce',), '0' * 64),
                          (('cert_fingerprint',), '0' * 64), (('phase',), 'boot_observed'),
                          (('debug_boot_facts', 'active_debug_mask'), 0x2000),
                          (('debug_boot_facts', 'bootplist_restore', 'data', 'timestamps'), False),
                          (('debug_boot_facts', 'netdump_active_control', 'remaining_profile', 'nondebug_sha256'), '0' * 64),
                          (('debug_boot_facts', 'owner_events', 0, 'source_identity'), '0' * 64)):
            changed = copy.deepcopy(check)
            summary = json.loads(changed['output']['summary'])
            target = summary
            for key in path[:-1]: target = target[key]
            target[path[-1]] = bad
            changed['output']['summary'] = json.dumps(summary)
            with self.subTest(path=path), self.assertRaises(ValueError): n.core_snapshot(changed, scope, plan.public_fact())
        with self.assertRaises(ValueError): dataclasses.replace(scope, boot_uuid=self.B1)
        for key, bad in (('id', 10), ('app', None), ('head_sha', '0' * 40), ('external_id', 'foreign'),
                         ('name', 'foreign'), ('status', 'completed'), ('conclusion', 'neutral')):
            with self.assertRaises(ValueError): n.core_snapshot({**check, key: bad}, scope, plan.public_fact())

    def prime_proof(self):
        plan, scope = self.prime_plan(), self.prime_scope()
        snapshot = n.core_snapshot(self.core_check(), scope, plan.public_fact())
        host = n.prime_host_fact(plan, scope, n.Endpoint('1.1.1.1', 49000), snapshot, n.HelloStats(True, True, 30))
        return n.make_prime_proof(plan.offer, plan.public_fact(), host, n.HelloStats(True, True, 35), snapshot, 11, 10)

    def test_prime_proof_is_userspace_only_and_rejects_scope_control_and_b1_packet_replay(self):
        proof, scope = self.prime_proof(), self.prime_scope()
        control = proof['core_snapshot']['facts']['netdump_active_control']
        self.assertEqual(n.validate_prime_proof(proof, scope, control), proof)
        self.assertEqual(proof['transport'], 'userspace_udp_only')
        self.assertNotEqual(proof['host_plan']['intel_public_endpoint'], self.prime_plan().intel_endpoint.record())
        self.assertNotIn('192.168.64', n.canonical(proof))
        for path, bad in ((('scope', 'nonce'), '0' * 64), (('scope', 'boot_uuid'), self.B1),
                          (('scope', 'core_identity'), '0' * 64), (('scope', 'cert_fingerprint'), '0' * 64),
                          (('host_plan', 'packet_nonce'), self.prime_plan().nonce[:32]),
                          (('host_plan', 'interface_sha256'), '0' * 64),
                          (('host_plan', 'core_summary_sha256'), '0' * 64),
                          (('receiver_stats', 'hello_received'), False), (('receiver_check_id',), True),
                          (('offer', 'purpose'), 'discovery')):
            value = copy.deepcopy(proof)
            target = value
            for key in path[:-1]: target = target[key]
            target[path[-1]] = bad
            with self.subTest(path=path), self.assertRaises(ValueError): n.validate_prime_proof(value, scope.record(), control)
        with self.assertRaises(ValueError): n.validate_prime_proof({**proof, 'raw': 'secret'}, scope, control)
        for changed in (dataclasses.replace(scope, nonce='0' * 64), dataclasses.replace(scope, recovery_check_id=12)):
            with self.assertRaises(ValueError): n.validate_prime_proof(proof, changed, control)
        bad = copy.deepcopy(control)
        bad['full_profile']['nondebug_sha256'] = '0' * 64
        with self.assertRaises(ValueError): n.validate_prime_proof(proof, scope, bad)

    def test_prime_adoption_requires_same_once_accepted_tuple_and_core_digest(self):
        plan, scope = self.prime_plan(), self.prime_scope()
        snapshot = n.core_snapshot(self.core_check(), scope, plan.public_fact())
        probe = n.prime_host_fact(plan, scope, n.Endpoint('1.1.1.1', 49000), snapshot)
        final = n.prime_host_fact(plan, scope, n.Endpoint('1.1.1.1', 49000), snapshot, n.HelloStats(True, True, 30))
        self.assertEqual(n.validate_prime_transition(probe, final, plan.offer, plan.public_fact()), final)
        for path, value in ((('intel_public_endpoint', 'port'), 49001), (('core_summary_sha256',), '0' * 64)):
            changed = copy.deepcopy(final)
            target = changed
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with self.assertRaises(ValueError): n.validate_prime_transition(probe, changed, plan.offer, plan.public_fact())

    def test_waiting_b2_accepts_one_exact_canonical_probe_before_hello(self):
        plan, scope = self.prime_plan(), self.prime_scope()
        snapshot = n.core_snapshot(self.core_check(), scope, plan.public_fact())
        probe = n.prime_host_fact(plan, scope, n.Endpoint('1.1.1.1', 49000), snapshot)
        waiting = n.waiting_fact(plan.offer, plan.public_fact())
        self.assertIsNone(waiting['accepted_probe'])
        accepted = n.waiting_fact(plan.offer, plan.public_fact(), probe, snapshot)
        self.assertEqual(n.validate_waiting(accepted, plan.offer, plan.public_fact(), probe), accepted)
        for key, bad in (('accepted_probe_sha256', '0' * 64), ('b1_plan_sha256', '0' * 64), ('phase', 'prime_ack')):
            with self.assertRaises(ValueError): n.validate_waiting({**accepted, key: bad}, plan.offer, plan.public_fact(), probe)
        altered = copy.deepcopy(accepted)
        altered['accepted_probe']['intel_public_endpoint']['port'] += 1
        altered['accepted_probe_sha256'] = n.digest(altered['accepted_probe'])
        with self.assertRaises(ValueError): n.validate_waiting(altered, plan.offer, plan.public_fact(), probe)

    def test_prime_checks_use_separate_neutral_namespace_and_reject_duplicate_scope(self):
        ctx, scope = self.context(), self.prime_scope()
        check = {'id': 10, 'name': 'Netdump prime plan 123', 'head_sha': 'a' * 40,
                 'external_id': 'netdump-prime/intel/123/1/' + 'a' * 40 + '/' + self.B2,
                 'app': {'id': 15368, 'slug': 'github-actions'}, 'details_url': 'https://github.com/Code-Hex/vz-ci-test/runs/10',
                 'status': 'completed', 'conclusion': 'neutral', 'output': {'summary': n.canonical({'phase': 'probe_ready'})}}
        self.assertTrue(n.check_identity(check, ctx, 'intel', prime=True, boot_uuid=self.B2))
        self.assertFalse(n.check_identity(check, ctx, 'intel'))
        self.assertEqual(n.check_payload(check, ctx, 'intel', prime=True), {'phase': 'probe_ready'})
        with self.assertRaises(ValueError): n.check_payload({**check, 'conclusion': 'success'}, ctx, 'intel', prime=True)
        duplicate = {**check, 'id': 12, 'name': 'foreign'}
        with self.assertRaises(ValueError): n.select_check({'total_count': 2, 'check_runs': [check, duplicate]}, ctx, 'intel', prime=True)

    def test_native_b1_residual_packet_cannot_satisfy_b2_domain_nonce(self):
        plan, scope = self.prime_plan(), self.prime_scope()
        host_nonce = n.prime_packet_nonce(scope, 'intel', plan.offer.nonce)
        receiver_nonce = n.prime_packet_nonce(scope, 'receiver', plan.offer.nonce)
        self.assertNotEqual(host_nonce, plan.nonce[:32])
        self.assertNotEqual(receiver_nonce, plan.offer.nonce)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(('127.0.0.1', 0)); b.bind(('127.0.0.1', 0))
            a.sendto(n.udp.PACKET.pack(b'KDP1', 1, bytes.fromhex(plan.nonce[:32]), bytes.fromhex(plan.offer.nonce), 1), b.getsockname())
            stats = n.udp.exchange(b, a.getsockname(), bytes.fromhex(receiver_nonce), bytes.fromhex(host_nonce), .2)
            self.assertFalse(stats['hello_received'])
            self.assertFalse(stats['ack_received'])
            with self.assertRaises(ValueError): n.HelloStats(stats['hello_received'], stats['ack_received'], stats['sent'])

    def test_prime_baseline_and_purpose_are_immutable_b1_facts(self):
        plan = self.prime_plan()
        self.assertEqual(n.DiscoveryPlan.from_record(plan.record()), plan)
        self.assertEqual(n.BootBaseline.from_record(plan.baseline.record()), plan.baseline)
        self.assertEqual(n.validate_host_fact(plan.public_fact(), plan.offer), plan.public_fact())
        self.assertEqual(plan.public_fact()['baseline'], plan.baseline.record())
        self.assertNotIn('en0', str(plan.public_fact()))
        for changes in ({'baseline': None}, {'offer': self.offer()}, {'baseline': {'raw': 'private'}}):
            with self.assertRaises(ValueError): dataclasses.replace(plan, **changes)
        for profile in ({'status': 'unavailable'}, {'status': 'observed', 'debug_mask': 0, 'nondebug_token_count': 0, 'nondebug_sha256': 'a' * 64},
                        {'status': 'observed', 'debug_mask': None, 'nondebug_token_count': True, 'nondebug_sha256': 'a' * 64}):
            with self.assertRaises(ValueError): n.BootBaseline.from_profile(self.B1, profile)
        with self.assertRaises(ValueError): dataclasses.replace(plan.offer, purpose='foreign')

    def context(self, role='intel'):
        return {'run': '123', 'attempt': '1', 'sha': 'a' * 40, 'role': role, 'port_mode': 'kernel-source'}

    def offer(self):
        return n.ReceiverOffer('123/1/' + 'a' * 40, 'b' * 32, n.Endpoint('8.8.8.8', 10248),
                               54321, 'c' * 64, 'd' * 64, tuple((key, 'e' * 64) for key in n.NETWORK_KEYS))

    def plan(self):
        return n.DiscoveryPlan(self.offer(), 'f' * 64, n.Endpoint('1.1.1.1', 48000),
                               '192.168.64.2', 'en0', NetdumpSettings('8.8.8.8', '192.168.64.1', 10248, 'f' * 16),
                               n.HelloStats(True, True, 40))

    def test_immutable_plan_roundtrip_and_public_private_boundary(self):
        plan = self.plan()
        self.assertEqual(n.DiscoveryPlan.from_record(plan.record()), plan)
        self.assertEqual(n.ReceiverOffer.from_record(plan.offer.record()), plan.offer)
        with self.assertRaises(dataclasses.FrozenInstanceError): plan.source_ipv4 = '10.0.0.1'
        with self.assertRaises(dataclasses.FrozenInstanceError): plan.offer.endpoint.port = 1
        public = plan.public_fact()
        self.assertEqual(n.validate_host_fact(public, plan.offer), public)
        self.assertNotIn('192.168.64', str(public))
        self.assertNotIn('en0', str(public))
        self.assertEqual(public['local_port'], 10248)
        self.assertEqual(public['receiver_endpoint'], {'ip': '8.8.8.8', 'port': 10248})
        for value in (dict(plan.record(), raw='secret'), dict(plan.record(), source_ipv4='127.0.0.1')):
            with self.assertRaises(ValueError): n.DiscoveryPlan.from_record(value)

    def test_offer_requires_same_context_sources_cert_and_immutable_ports(self):
        offer = self.offer()
        self.assertEqual(n.match_offer(offer.record(), self.context(), 'c' * 64, 'd' * 64, dict(offer.network_sources)), offer)
        for field, value in (('binding', '999/1/' + 'a' * 40), ('cert_fingerprint', '0' * 64),
                             ('core_identity', '0' * 64), ('network_sources', {}), ('nonce', 'bad'),
                             ('endpoint', {'ip': '8.8.8.8', 'port': 41139}), ('local_port', True)):
            bad = {**offer.record(), field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                n.match_offer(bad, self.context(), 'c' * 64, 'd' * 64, dict(offer.network_sources))

    def test_host_phases_preserve_immutable_fields_and_ack_binds_exact_plan(self):
        plan = self.plan()
        ready = dataclasses.replace(plan, stats=None).public_fact()
        final = plan.public_fact()
        self.assertEqual(n.validate_host_fact(ready, plan.offer), ready)
        self.assertEqual(n.plan_base(ready), n.plan_base(final))
        ack = n.ack_fact(plan.offer, final, n.HelloStats(True, True, 30))
        self.assertEqual(n.validate_ack(ack, plan.offer, final), ack)
        for field, value in (('nonce', '0' * 64), ('local_port', 41139), ('receiver_nonce', '0' * 32),
                             ('receiver_offer_digest', '0' * 64), ('core_identity', '0' * 64),
                             ('cert_fingerprint', '0' * 64), ('network_sources', {}), ('stats', {'hello_received': False, 'ack_received': True, 'sent': 2}),
                             ('phase', 'foreign')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                n.validate_host_fact({**final, field: value}, plan.offer, expected_nonce=plan.nonce)
        bad = copy.deepcopy(ack)
        bad['plan']['intel_public_endpoint']['port'] += 1
        with self.assertRaises(ValueError): n.validate_ack(bad, plan.offer, final)
        low_offer = dataclasses.replace(plan.offer, endpoint=n.Endpoint('8.8.8.8', 1))
        low_plan = dataclasses.replace(plan, offer=low_offer, settings=dataclasses.replace(plan.settings, port=1))
        bad = low_plan.public_fact()
        bad['receiver_endpoint']['port'] = True
        with self.assertRaises(ValueError): n.validate_host_fact(bad, low_offer)
        low_offer = dataclasses.replace(plan.offer, local_port=1)
        low_plan = dataclasses.replace(plan, offer=low_offer)
        bad = n.ack_fact(low_offer, low_plan.public_fact(), n.HelloStats(True, True, 30))
        bad['offer']['local_port'] = True
        with self.assertRaises(ValueError): n.validate_ack(bad, low_offer, low_plan.public_fact())

    def test_route_is_numeric_unique_bounded_and_has_no_fallback(self):
        self.assertEqual(n.parse_route(b'route to: 8.8.8.8\n gateway: 192.168.64.1\n interface: en0\n'), ('192.168.64.1', 'en0'))
        for raw in (b'gateway: link#2\ninterface: en0\n', b'gateway: 192.168.64.1\n',
                    b'gateway: 192.168.64.1\ngateway: 10.0.0.1\ninterface: en0\n',
                    b'gateway: 192.168.64.1\ngateway: invalid extra\ninterface: en0\n',
                    b'gateway: 192.168.64.1\ninterface: en0\ninterface: invalid extra\n',
                    b'gateway: 0.1.2.3\ninterface: en0\n', b'x' * 8193, b'gateway: 10.0.0.1\ninterface: /private/x\n'):
            with self.assertRaises(ValueError): n.parse_route(raw)

    def test_check_selection_rejects_duplicate_foreign_identity_and_incomplete_page(self):
        ctx = self.context()
        check = {'id': 9, 'name': 'Netdump plan 123', 'head_sha': 'a' * 40,
                 'external_id': 'netdump/intel/123/1/' + 'a' * 40,
                 'app': {'id': 15368, 'slug': 'github-actions'},
                 'details_url': 'https://github.com/Code-Hex/vz-ci-test/runs/9'}
        self.assertEqual(n.select_check({'total_count': 1, 'check_runs': [check]}, ctx, 'intel'), check)
        for listing in ({'total_count': 2, 'check_runs': [check]}, {'total_count': 2, 'check_runs': [check, check]},
                        {'total_count': 1, 'check_runs': [{**check, 'app': {'id': 1, 'slug': 'foreign'}}]},
                        {'total_count': True, 'check_runs': [check]}):
            with self.assertRaises(ValueError): n.select_check(listing, ctx, 'intel')

    def test_operation_budget_reserves_cleanup_even_with_short_outer_timer(self):
        self.assertEqual(n.operation_deadline(180, 0), 156)
        for deadline in (24, 12, 0, -1):
            with self.assertRaises(TimeoutError): n.operation_deadline(deadline, 0)

    def test_cleanup_distinguishes_unattempted_creation_from_unknown_server_result(self):
        owner = n.CheckOwner(self.context(), 'unused', 'intel', -1)
        self.assertEqual(owner.cleanup(), 'not_created')
        owner.attempted = True
        self.assertEqual(owner.cleanup(), 'not_acknowledged')
        owner.check_id = 9
        self.assertEqual(owner.cleanup(), 'not_acknowledged')

    def test_receiver_ack_requires_successful_canonical_own_check(self):
        value = n.ack_fact(self.offer(), self.plan().public_fact(), n.HelloStats(True, True, 30))
        ctx = self.context('receiver')
        check = {'id': 9, 'name': 'Netdump receiver 123', 'head_sha': 'a' * 40,
                 'external_id': 'netdump/receiver/123/1/' + 'a' * 40,
                 'app': {'id': 15368, 'slug': 'github-actions'},
                 'details_url': 'https://github.com/Code-Hex/vz-ci-test/runs/9',
                 'status': 'completed', 'conclusion': 'success', 'output': {'summary': n.canonical(value)}}
        self.assertEqual(n.check_payload(check, ctx, 'receiver'), value)
        for field, bad in (('status', 'in_progress'), ('conclusion', 'failure'), ('app', None)):
            with self.assertRaises(ValueError): n.check_payload({**check, field: bad}, ctx, 'receiver')

    def test_connected_adapter_runs_existing_hello_ack_on_real_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(('127.0.0.1', 0)); b.bind(('127.0.0.1', 0))
            address = b.getsockname()
            a.connect(address)
            adapter = n.ConnectedPeer(a, address)
            self.assertEqual(adapter.fileno(), a.fileno())
            result = {}
            def receive():
                result['receiver'] = n.udp.exchange(b, a.getsockname(), b'b' * 16, b'a' * 16, 1)
            thread = threading.Thread(target=receive)
            thread.start()
            result['host'] = n.udp.exchange(adapter, address, b'a' * 16, b'b' * 16, 1)
            thread.join(2)
            self.assertFalse(thread.is_alive())
            for stats in result.values():
                self.assertTrue(stats['hello_received'])
                self.assertTrue(stats['ack_received'])
            self.assertEqual(set(result), {'receiver', 'host'})
            with self.assertRaises(ValueError): adapter.sendto(b'no', ('127.0.0.1', address[1] + 1))

    def test_private_plan_file_is_exclusive_private_and_public_fact_redacts_route(self):
        plan = self.plan()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'plan.json'
            n.write_file(target, plan.record(), 0o600)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(n.DiscoveryPlan.from_record(json.loads(target.read_text())), plan)
            with self.assertRaises(FileExistsError): n.write_file(target, plan.public_fact(), 0o600)
            target.unlink()
            other = Path(directory) / 'other'
            other.write_text('unchanged')
            target.symlink_to(other)
            with self.assertRaises(FileExistsError): n.write_file(target, plan.record(), 0o600)
            self.assertEqual(other.read_text(), 'unchanged')
            public = n.canonical(plan.public_fact())
            self.assertNotIn(plan.source_ipv4, public)
            self.assertNotIn(plan.settings.router_ipv4, public)
            self.assertNotIn(plan.interface, public)


if __name__ == '__main__': unittest.main()
