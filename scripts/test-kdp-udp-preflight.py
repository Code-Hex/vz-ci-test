import importlib.util
import json
import os
import tempfile
import socket
import struct
import threading
import time
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("udp", Path(__file__).with_name("kdp-udp-preflight.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Udp(unittest.TestCase):
    def wire_state(self, role='receiver'):
        import base64
        import hashlib
        return {'port_mode': 'crashdump-wire', 'role': role, 'result': 'established',
                'wire_transfer': {'status': 'complete', 'scope': 'synthetic_crashdump_udp_only',
                                  'bytes': 1200, 'sha256': 'a' * 64, 'filename_sha256': 'b' * 64},
                'wire_cert_fingerprint': 'c' * 64,
                'wire_sources': {key: 'd' * 64 for key in ('preflight_sha256', 'codec_sha256', 'reports_sha256')},
                'wire_envelope': {'ciphertext': base64.b64encode(b'encrypted').decode(),
                                  'cipher_sha256': hashlib.sha256(b'encrypted').hexdigest(),
                                  'cert_fingerprint': 'c' * 64}}

    def test_wire_artifact_fails_closed_and_filters_unpublished_fields(self):
        state = self.wire_state()
        state.update(raw_payload='private', token='secret')
        self.assertEqual(r.sanitize_state(state)['result'], 'established')
        self.assertNotIn('private', json.dumps(r.sanitize_state(state)))
        self.assertNotIn('secret', json.dumps(r.sanitize_state(state)))
        for key in ('wire_transfer', 'wire_cert_fingerprint', 'wire_sources', 'wire_envelope'):
            with self.subTest(key=key):
                invalid = {k: v for k, v in state.items() if k != key}
                self.assertNotEqual(r.sanitize_state(invalid)['result'], 'established')

    def test_wire_peer_requires_identical_sources_certificate_and_transfer(self):
        state, peer = self.wire_state('intel'), self.wire_state()
        self.assertTrue(r.wire_pair_matches(state, peer))
        for key, value in [('wire_sources', {}), ('wire_cert_fingerprint', 'e' * 64),
                           ('wire_transfer', {}), ('wire_envelope', {})]:
            self.assertFalse(r.wire_pair_matches(state, dict(peer, **{key: value})))

    def test_wire_commit_failure_withholds_eof_ack(self):
        data = b'VZ_SYNTHETIC_NON_KERNEL\nvalue'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(('127.0.0.1', 0)); b.bind(('127.0.0.1', 0))
            failures = []
            def receive():
                try:
                    r.wire_exchange(b, a.getsockname(), 'receiver', 'fixture', data, lambda value: False, seconds=1)
                except ValueError as exc:
                    failures.append(str(exc))
            thread = threading.Thread(target=receive)
            thread.start()
            with self.assertRaises(TimeoutError):
                r.wire_exchange(a, b.getsockname(), 'intel', 'fixture', data, None, seconds=1)
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, ['wire_commit_unconfirmed'])

    def test_synthetic_wire_fixture_is_role_independent_and_never_a_kernel_panic(self):
        a, b = b'a' * 16, b'b' * 16
        sender = r.wire_fixture(self.context(mode='crashdump-wire'), a, b)
        receiver = r.wire_fixture(self.context('receiver', 'crashdump-wire'), b, a)
        self.assertEqual(sender, receiver)
        self.assertEqual(len(sender[0]), 16)
        self.assertTrue(sender[1].startswith(b'VZ_SYNTHETIC_NON_KERNEL\n'))
        self.assertGreater(len(sender[1]), 1024)
        self.assertLessEqual(len(sender[1]), 12288)
        self.assertNotIn(b'panic(cpu', sender[1])
        peer = self.ready(self.context(mode='crashdump-wire'), 'receiver')
        self.assertEqual(r.bind_port(self.context(mode='crashdump-wire'), peer), 46272)
        with self.assertRaises(ValueError):
            r.bind_port(self.context(mode='crashdump-wire'), dict(peer, endpoint={'ip': '1.1.1.1', 'port': 41139}))

    def test_synthetic_transfer_over_real_udp_commits_before_final_ack(self):
        data = b'VZ_SYNTHETIC_NON_KERNEL\n' + b'x' * 1200
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(('127.0.0.1', 0)); b.bind(('127.0.0.1', 0))
            result, committed = {}, []
            def commit(value):
                time.sleep(4.2)
                committed.append(value)
                return True
            def receive():
                result['receiver'] = r.wire_exchange(b, a.getsockname(), 'receiver', 'fixture', data,
                    commit, seconds=8)
            thread = threading.Thread(target=receive)
            thread.start()
            a.sendto(r.PACKET.pack(b'KDP1', 1, b'a' * 16, b'b' * 16, 1), b.getsockname())
            result['sender'] = r.wire_exchange(a, b.getsockname(), 'intel', 'fixture', data, None, seconds=8)
            thread.join(9)
            self.assertFalse(thread.is_alive())
            self.assertEqual(committed, [data])
            self.assertEqual(result['receiver'], result['sender'])
            self.assertEqual(result['sender']['status'], 'complete')
            self.assertEqual(result['sender']['bytes'], len(data))

    def response(self, tx, port=43210, ip="1.1.1.1"):
        mapped = struct.pack("!BBHI", 0, 1, port ^ 0x2112, int.from_bytes(socket.inet_aton(ip), "big") ^ r.COOKIE)
        attr = struct.pack("!HH", 0x20, len(mapped)) + mapped
        return struct.pack("!HHI12s", 0x0101, len(attr), r.COOKIE, tx) + attr

    def context(self, role="intel", mode="kernel-source"):
        return {"run": "123", "attempt": "1", "sha": "a" * 40, "role": role, "port_mode": mode}

    def ready(self, ctx, role, port=46272):
        return {"phase": "ready", "role": role, "binding": r.binding(ctx, role),
                "port_mode": ctx["port_mode"], "nonce": "ab" * 16,
                "endpoint": {"ip": "1.1.1.1", "port": port}}

    def test_port_mode_defaults_and_rejects_unknown_values(self):
        self.assertEqual(r.port_mode(), "symmetric")
        self.assertEqual(r.port_mode("kernel-source"), "kernel-source")
        for value in ("", "kernel", "SYMMETRIC", None, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.port_mode(value)

    def test_kernel_source_bind_requires_valid_receiver_ready(self):
        ctx = self.context()
        peer = self.ready(ctx, "receiver")
        self.assertEqual(r.bind_port(ctx, peer), 46272)
        self.assertEqual(r.bind_port(self.context("receiver")), 41139)
        self.assertEqual(r.bind_port(self.context(mode="symmetric")), 41139)
        invalid = [None, dict(peer, port_mode="symmetric"), dict(peer, phase="init"),
                   dict(peer, role="intel"), dict(peer, binding="other"), dict(peer, nonce="bad"),
                   dict(peer, result="unsupported"), dict(peer, endpoint={"ip": "127.0.0.1", "port": 46272}),
                   dict(peer, endpoint={"ip": "1.1.1.1", "port": True})]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.bind_port(ctx, value)

    def test_peer_metadata_rejects_cross_mode_checks(self):
        ctx = self.context()
        peer = self.ready(ctx, "receiver")
        self.assertEqual(r.peer_metadata(peer, ctx, "receiver"), peer)
        for value in (dict(peer, port_mode="symmetric"), {k: v for k, v in peer.items() if k != "port_mode"}):
            with self.assertRaises(ValueError):
                r.peer_metadata(value, ctx, "receiver")

    def test_kernel_source_mutual_port_pair(self):
        intel = {"role": "intel", "port_mode": "kernel-source", "local_port": 46272,
                 "peer_public_port": 46272, "endpoint": {"ip": "1.1.1.1", "port": 37650}}
        receiver = {"role": "receiver", "port_mode": "kernel-source", "local_port": 41139,
                    "peer_public_port": 37650, "endpoint": {"ip": "8.8.8.8", "port": 46272}}
        self.assertTrue(r.port_pair_matches(intel, receiver))
        self.assertTrue(r.port_pair_matches(receiver, intel))
        for value in (dict(intel, local_port=41139), dict(intel, local_port=True),
                      dict(intel, peer_public_port=41139), dict(intel, port_mode="symmetric"),
                      dict(intel, role="receiver"), dict(intel, endpoint={"ip": "1.1.1.1", "port": 37651})):
            self.assertFalse(r.port_pair_matches(value, receiver))
            self.assertFalse(r.port_pair_matches(receiver, value))
        self.assertFalse(r.port_pair_matches(intel, dict(receiver, local_port=46272)))
        symmetric_intel = dict(intel, port_mode="symmetric", local_port=41139)
        symmetric_receiver = dict(receiver, port_mode="symmetric")
        self.assertTrue(r.port_pair_matches(symmetric_intel, symmetric_receiver))

    def test_port_facts_are_bounded_in_artifact(self):
        safe = r.sanitize_state({"port_mode": "kernel-source", "local_port": 46272, "peer_public_port": 46272})
        self.assertEqual(safe["port_mode"], "kernel-source")
        self.assertEqual(safe["local_port"], 46272)
        self.assertEqual(safe["peer_public_port"], 46272)
        for value in (True, 0, 65536, "46272"):
            safe = r.sanitize_state({"port_mode": "other", "local_port": value, "peer_public_port": value})
            self.assertNotIn("port_mode", safe)
            self.assertNotIn("local_port", safe)
            self.assertNotIn("peer_public_port", safe)

    def test_artifact_contains_only_sanitized_facts(self):
        state = {"role": "intel", "result": "not_established", "reason": "probe_incomplete",
                 "nonce": "ab" * 16, "endpoint": {"ip": "1.1.1.1", "port": 43210},
                 "stats": {"sent": 60, "hello_received": True, "ack_received": False},
                 "token": "secret", "raw": "secret", "error": "secret"}
        safe = r.sanitize_state(state)
        self.assertNotIn("token", safe)
        self.assertNotIn("raw", safe)
        self.assertNotIn("error", safe)
        self.assertEqual(safe["endpoint"], state["endpoint"])
        self.assertEqual(safe["result"], "not_established")
        self.assertNotIn("secret", str(safe))

    def test_atomic_artifact_sanitizes_prepatch_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.environ.get("RUNNER_TEMP")
            os.environ["RUNNER_TEMP"] = tmp
            try:
                r.artifact_written = False
                r.artifact_failed = False
                r.persist_state({"result": "not_established", "role": "intel", "check_update": "not_confirmed", "token": "secret"})
                saved = json.loads((Path(tmp) / "debug/kdp-udp-preflight.json").read_text())
                self.assertEqual(saved["result"], "not_established")
                self.assertEqual(saved["check_update"], "not_confirmed")
                self.assertNotIn("secret", str(saved))
                self.assertTrue(r.artifact_written)
            finally:
                if previous is None:
                    os.environ.pop("RUNNER_TEMP", None)
                else:
                    os.environ["RUNNER_TEMP"] = previous

    def test_stun_response_and_bad_fields(self):
        tx = bytes(range(12))
        valid = self.response(tx)
        self.assertEqual(r.parse_stun(valid, tx), ("1.1.1.1", 43210))
        self.assertFalse(r.public_endpoint(16843009, 1234))
        for bad in [valid[:-1], bytes([1, 2]) + valid[2:], valid[:4] + bytes(4) + valid[8:],
                    valid[:8] + b"x" * 12 + valid[20:], self.response(tx, ip="127.0.0.1")]:
            with self.assertRaises(ValueError):
                r.parse_stun(bad, tx)
        with self.assertRaises(ValueError):
            r.parse_stun(valid + valid[20:], tx)

    def test_tlv_padding_and_duplicate(self):
        tx = bytes(range(12))
        valid = self.response(tx)
        duplicate = valid[20:] * 2
        with self.assertRaises(ValueError):
            r.parse_stun(struct.pack("!HHI12s", 0x0101, len(duplicate), r.COOKIE, tx) + duplicate, tx)
        bad = struct.pack("!HH", 0x9999, 3) + b"abc"
        with self.assertRaises(ValueError):
            r.parse_stun(struct.pack("!HHI12s", 0x0101, len(bad), r.COOKIE, tx) + bad, tx)

    def test_window_and_check_binding(self):
        stats = {"hello_received": True, "ack_received": True}
        self.assertEqual(r.window_outcome(stats, 1, 30_000_000_001, {"start_ns": 2, "end_ns": 30_000_000_002, "stats": {"hello_received": True, "ack_received": True}}), "established")
        self.assertEqual(r.window_outcome(stats, 1, 30_000_000_001, {"start_ns": 29_000_000_000, "end_ns": 60_000_000_000}), "window_unconfirmed")
        self.assertEqual(r.window_outcome(stats, 1, 30_000_000_001, {"start_ns": 2, "end_ns": 30_000_000_002, "stats": {"hello_received": True, "ack_received": False}}), "not_established")
        stats["ack_received"] = False
        self.assertEqual(r.window_outcome(stats, 1, 30_000_000_001, {"start_ns": 2, "end_ns": 30_000_000_002, "stats": {"hello_received": True, "ack_received": True}}), "not_established")
        ctx = {"run": "123", "attempt": "1", "sha": "a" * 40}
        check = {"id": 9, "name": "KDP UDP intel 123", "head_sha": ctx["sha"], "external_id": r.binding(ctx, "intel"),
                 "app": {"id": 15368, "slug": "github-actions"}, "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9"}
        self.assertTrue(r.check_identity(check, ctx, "intel"))
        self.assertFalse(r.check_identity(check, ctx, "receiver"))
        self.assertFalse(r.check_identity(dict(check, external_id="wrong"), ctx, "intel"))

    def test_stun_ignores_reply_from_other_source(self):
        client, server, outsider = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3))
        for sock in (client, server, outsider):
            self.addCleanup(sock.close)
            sock.bind(("127.0.0.1", 0))
        def reply():
            data, address = server.recvfrom(1024)
            tx = data[8:20]
            outsider.sendto(self.response(tx, ip="8.8.8.8"), address)
            server.sendto(self.response(tx, ip="1.1.1.1"), address)
        thread = threading.Thread(target=reply)
        thread.start()
        self.assertEqual(r.stun_binding(client, server.getsockname()), ("1.1.1.1", 43210))
        thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_mapping_audit_uses_one_socket_in_a_b_a_order(self):
        client, first, second = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3))
        for sock in (client, first, second):
            self.addCleanup(sock.close)
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(2)
        sources = []
        def replies(server, count, port):
            for _ in range(count):
                data, address = server.recvfrom(1024)
                sources.append(address)
                server.sendto(self.response(data[8:20], port=port), address)
        threads = [threading.Thread(target=replies, args=(first, 2, 40001)),
                   threading.Thread(target=replies, args=(second, 1, 40002))]
        for thread in threads:
            thread.start()
        endpoint, samples = r.audit_mappings(client, [first.getsockname(), second.getsockname(), first.getsockname()])
        for thread in threads:
            thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(endpoint, ("1.1.1.1", 40001))
        self.assertEqual([sample["port"] for sample in samples], [40001, 40002, 40001])
        self.assertEqual(sources, [client.getsockname()] * 3)

    def test_mapping_artifact_has_only_public_bounded_fields(self):
        state = {"mapping_samples": [{"server_ip": "1.1.1.1", "state": "observed", "ip": "8.8.8.8", "port": 40001, "token": "secret"},
                                     {"server_ip": "127.0.0.1", "state": "observed", "ip": "8.8.8.8", "port": 40002}]}
        saved = r.sanitize_state(state)
        self.assertEqual(saved["mapping_samples"], [{"server_ip": "1.1.1.1", "state": "observed", "ip": "8.8.8.8", "port": 40001}])
        self.assertNotIn("secret", str(saved))

    def test_unknown_source_is_not_acknowledged(self):
        one = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        expected = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        outsider = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for sock in (one, expected, outsider):
            self.addCleanup(sock.close)
            sock.bind(("127.0.0.1", 0))
        a, b = bytes(range(16)), bytes(range(16, 32))
        results = []
        thread = threading.Thread(target=lambda: results.append(r.exchange(one, expected.getsockname(), a, b, 0.4)))
        thread.start()
        outsider.sendto(r.PACKET.pack(b"KDP1", 1, b, a, 7), one.getsockname())
        outsider.settimeout(0.6)
        with self.assertRaises(TimeoutError):
            outsider.recvfrom(1024)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["valid_peer_port_mismatches"], 1)
        self.assertEqual(results[0]["other_peer_ports"], [outsider.getsockname()[1]])
        self.assertFalse(results[0]["hello_received"])

    def test_loopback_pair_hello_ack(self):
        one = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        two = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(one.close)
        self.addCleanup(two.close)
        one.bind(("127.0.0.1", 0))
        two.bind(("127.0.0.1", 0))
        a, b = bytes(range(16)), bytes(range(16, 32))
        result = {}
        thread = threading.Thread(target=lambda: result.setdefault("one", r.exchange(one, two.getsockname(), a, b, 1.2)))
        thread.start()
        result["two"] = r.exchange(two, one.getsockname(), b, a, 1.2)
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(result["one"]["hello_received"] and result["one"]["ack_received"])
        self.assertTrue(result["two"]["hello_received"] and result["two"]["ack_received"])
        self.assertLessEqual(result["one"]["sent"], 300)


if __name__ == "__main__":
    unittest.main()
