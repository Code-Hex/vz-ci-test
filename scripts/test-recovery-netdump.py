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
