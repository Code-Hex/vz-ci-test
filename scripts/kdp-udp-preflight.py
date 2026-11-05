#!/usr/bin/env python3
"""Same-run userspace UDP/STUN and synthetic crashdump checks; no kernel data."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

import kdp_crashdump as wire
import recovery_reports as reports

COOKIE = 0x2112A442
UUID = "87453B1D-A163-31FA-B33B-0FB4BE78E6E8"
API = "https://api.github.com/repos/Code-Hex/vz-ci-test"
CHECKS = API + "/check-runs"
PACKET = struct.Struct("!4sB16s16sI")
artifact_written = False
artifact_failed = False


def public_endpoint(ip, port):
    try:
        if not isinstance(ip, str):
            return False
        address = ipaddress.ip_address(ip)
        return address.version == 4 and str(address) == ip and address.is_global and type(port) is int and 0 < port < 65536
    except (ValueError, TypeError):
        return False


def parse_stun(data, transaction):
    if len(data) < 20 or len(transaction) != 12:
        raise ValueError("STUN header")
    kind, size, cookie, tx = struct.unpack("!HHI12s", data[:20])
    if kind != 0x0101 or cookie != COOKIE or tx != transaction or size != len(data) - 20 or size % 4:
        raise ValueError("STUN header mismatch")
    pos, mapped = 20, []
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError("STUN attribute header")
        typ, length = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        padded = (length + 3) & ~3
        if pos + padded > len(data):
            raise ValueError("STUN attribute bounds")
        value = data[pos:pos + length]
        if typ == 0x0020:
            if length != 8:
                raise ValueError("STUN mapped length")
            zero, family, port, address = struct.unpack("!BBHI", value)
            if zero != 0 or family != 1:
                raise ValueError("STUN mapped family")
            ip = socket.inet_ntoa(struct.pack("!I", address ^ COOKIE))
            port ^= COOKIE >> 16
            if not public_endpoint(ip, port):
                raise ValueError("STUN address is not public IPv4")
            mapped.append((ip, port))
        pos += padded
    if len(mapped) != 1:
        raise ValueError("STUN mapped count")
    return mapped[0]


def stun_binding(sock, server):
    tx = os.urandom(12)
    request = struct.pack("!HHI12s", 0x0001, 0, COOKIE, tx)
    deadline = time.monotonic() + 5
    next_send, interval, requests = 0, 0.5, 0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_send and requests < 5:
            sock.sendto(request, server)
            requests += 1
            next_send, interval = now + interval, min(2, interval * 2)
        readable, _, _ = select.select([sock], [], [], min(0.2, max(0, deadline - now)))
        if readable:
            data, source = sock.recvfrom(4096)
            if source == server:
                try:
                    return parse_stun(data, tx)
                except ValueError:
                    continue
    raise TimeoutError("STUN unavailable")


def audit_mappings(sock, servers):
    targets = list(dict.fromkeys(servers))[:2]
    if not targets:
        raise ValueError("STUN endpoint absent")
    samples, endpoint = [], None
    for server in targets + targets[:1]:
        sample = {"server_ip": server[0], "state": "unavailable"}
        try:
            mapped = stun_binding(sock, server)
            sample.update({"state": "observed", "ip": mapped[0], "port": mapped[1]})
            if server == targets[0]:
                endpoint = mapped
        except (OSError, ValueError):
            pass
        samples.append(sample)
    return endpoint, samples


def exchange(sock, peer, own_nonce, peer_nonce, seconds):
    if len(own_nonce) != 16 or len(peer_nonce) != 16 or own_nonce == peer_nonce:
        raise ValueError("nonce invalid")
    deadline = time.monotonic() + seconds
    next_send, sequence = 0, 0
    sent_sequences = set()
    sent, hello_received, ack_received = 0, False, False
    port_mismatches, other_ports = 0, set()
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_send and sent < 280:
            sequence += 1
            sock.sendto(PACKET.pack(b"KDP1", 1, own_nonce, peer_nonce, sequence), peer)
            sent_sequences.add(sequence)
            sent += 1
            next_send = now + 0.5
        readable, _, _ = select.select([sock], [], [], min(0.1, max(0, deadline - now)))
        if not readable:
            continue
        data, source = sock.recvfrom(1024)
        if source[0] != peer[0] or len(data) != PACKET.size:
            continue
        magic, kind, sender, receiver, number = PACKET.unpack(data)
        if (magic != b"KDP1" or sender != peer_nonce or receiver != own_nonce or number == 0
                or kind not in (1, 2) or (kind == 2 and number not in sent_sequences)):
            continue
        if source != peer:
            port_mismatches += 1
            if len(other_ports) < 8:
                other_ports.add(source[1])
            continue
        if kind == 1:
            hello_received = True
            if sent < 280:
                sock.sendto(PACKET.pack(b"KDP1", 2, own_nonce, peer_nonce, number), peer)
                sent += 1
        elif kind == 2 and number in sent_sequences:
            ack_received = True
    return {"hello_received": hello_received, "ack_received": ack_received, "sent": sent,
            "valid_peer_port_mismatches": port_mismatches, "other_peer_ports": sorted(other_ports)}


def binding(ctx, role):
    return "/".join((ctx["run"], ctx["attempt"], ctx["sha"], role))


def port_mode(value="symmetric"):
    if value not in ("symmetric", "kernel-source", "crashdump-wire"):
        raise ValueError("port mode rejected")
    return value


def peer_metadata(data, ctx, role):
    if (not isinstance(data, dict) or data.get("binding") != binding(ctx, role) or
            data.get("role") != role or data.get("port_mode") != ctx["port_mode"]):
        raise ValueError("peer binding or port mode")
    return data


def peer_endpoint(peer, own_nonce=None):
    remote, nonce = peer.get("endpoint"), peer.get("nonce")
    if (peer.get("phase") not in ("ready", "probing", "result") or peer.get("result") == "unsupported" or
            not isinstance(remote, dict) or not public_endpoint(remote.get("ip", ""), remote.get("port")) or
            not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce) or nonce == own_nonce):
        raise ValueError("peer metadata invalid")
    return (remote["ip"], remote["port"]), bytes.fromhex(nonce)


def bind_port(ctx, peer=None):
    if ctx["port_mode"] in ("kernel-source", "crashdump-wire") and ctx["role"] == "intel":
        peer_metadata(peer, ctx, "receiver")
        port = peer_endpoint(peer)[0][1]
        if ctx["port_mode"] == "crashdump-wire" and port == 41139:
            raise ValueError("interactive port excluded")
        return port
    return 41139


def port_pair_matches(state, peer):
    if (state.get("port_mode") not in ("symmetric", "kernel-source", "crashdump-wire") or
            peer.get("port_mode") != state["port_mode"] or
            {state.get("role"), peer.get("role")} != {"intel", "receiver"}):
        return False
    for item in (state, peer):
        endpoint = item.get("endpoint")
        if (not isinstance(endpoint, dict) or not public_endpoint(endpoint.get("ip", ""), endpoint.get("port")) or
                any(type(item.get(key)) is not int or not 0 < item[key] < 65536
                    for key in ("local_port", "peer_public_port"))):
            return False
    if (state["peer_public_port"] != peer["endpoint"]["port"] or
            peer["peer_public_port"] != state["endpoint"]["port"]):
        return False
    if state["port_mode"] == "symmetric":
        return state["local_port"] == peer["local_port"] == 41139
    intel, receiver = (state, peer) if state["role"] == "intel" else (peer, state)
    return (receiver["local_port"] == 41139 and intel["local_port"] == receiver["endpoint"]["port"] and
            (state["port_mode"] != "crashdump-wire" or intel["local_port"] != 41139))


def validate_context():
    ctx = {"run": os.getenv("GITHUB_RUN_ID", ""), "attempt": os.getenv("GITHUB_RUN_ATTEMPT", ""),
           "sha": os.getenv("GITHUB_SHA", ""), "role": os.getenv("KDP_ROLE", ""),
           "port_mode": port_mode(os.getenv("KDP_PORT_MODE", "symmetric"))}
    if (os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("GITHUB_EVENT_NAME") != "workflow_dispatch" or
            os.getenv("GITHUB_REPOSITORY") != "Code-Hex/vz-ci-test" or os.getenv("GITHUB_REF") != "refs/heads/main" or
            os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or not os.getenv("RUNNER_TEMP") or
            not Path(os.environ["RUNNER_TEMP"]).is_dir() or ctx["role"] not in ("intel", "receiver") or
            not re.fullmatch(r"[1-9][0-9]{0,19}", ctx["run"]) or
            not re.fullmatch(r"[1-9][0-9]{0,4}", ctx["attempt"]) or
            not re.fullmatch(r"[0-9a-f]{40}", ctx["sha"]) or
            os.getenv("KDP_STUN_HOST") != "stun.cloudflare.com" or os.getenv("KDP_STUN_PORT") != "3478"):
        raise ValueError("context rejected")
    system = subprocess.check_output(["/usr/bin/uname", "-s"], text=True, timeout=5).strip()
    machine = subprocess.check_output(["/usr/bin/uname", "-m"], text=True, timeout=5).strip()
    if machine != "x86_64" or system != ("Darwin" if ctx["role"] == "intel" else "Linux"):
        raise ValueError("platform rejected")
    if ctx["role"] == "intel":
        live = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.uuid"], text=True, timeout=5).strip().upper()
        file = subprocess.check_output(["xcrun", "dwarfdump", "--uuid", "/System/Library/Kernels/kernel"], text=True, timeout=20)
        matches = re.findall(r"UUID:\s*([0-9A-Fa-f-]+)\s*\(x86_64\)", file)
        if live != UUID or matches != [UUID]:
            raise ValueError("kernel guard rejected")
    return ctx


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(method, path, token, payload=None):
    if not (path == "/check-runs" or re.fullmatch(r"/check-runs/[1-9][0-9]*", path) or
            re.fullmatch(r"/commits/[0-9a-f]{40}/check-runs\?filter=all&per_page=100", path)):
        raise ValueError("API endpoint rejected")
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(API + path, method=method, data=data, headers={"Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json", "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "vz-udp-preflight"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=8) as response:
        return json.load(response)


def check_identity(check, ctx, role):
    number = check.get("id")
    return (type(number) is int and number > 0 and check.get("name") == "KDP UDP " + role + " " + ctx["run"] and
            check.get("head_sha") == ctx["sha"] and check.get("external_id") == binding(ctx, role) and
            check.get("app", {}).get("id") == 15368 and check.get("app", {}).get("slug") == "github-actions" and
            check.get("details_url") == "https://github.com/Code-Hex/vz-ci-test/runs/" + str(number))


def peer_check(ctx, token, role):
    listing = api("GET", "/commits/" + ctx["sha"] + "/check-runs?filter=all&per_page=100", token)
    checks = listing.get("check_runs", [])
    if listing.get("total_count", 0) > len(checks):
        raise ValueError("check list incomplete")
    matches = [item for item in checks if check_identity(item, ctx, role)]
    if len(matches) > 1:
        raise ValueError("duplicate peer")
    if not matches:
        return None
    data = json.loads(matches[0].get("output", {}).get("summary", "{}"))
    return peer_metadata(data, ctx, role)


def wait_peer(ctx, token, role, own_nonce):
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        candidate = peer_check(ctx, token, role)
        if candidate and candidate.get("phase") in ("ready", "probing", "result"):
            if candidate.get("result") == "unsupported":
                return None
            peer_endpoint(candidate, own_nonce)
            return candidate
        time.sleep(1)
    return None


def update(check_id, token, data, conclusion=None):
    payload = {"output": {"title": "UDP path preflight", "summary": json.dumps(data, separators=(",", ":"))}}
    if conclusion:
        payload.update({"status": "completed", "conclusion": conclusion})
    api("PATCH", "/check-runs/" + str(check_id), token, payload)


def window_outcome(stats, start_ns, end_ns, peer):
    pstart, pend = peer.get("start_ns"), peer.get("end_ns")
    if type(pstart) is not int or type(pend) is not int or pstart >= pend or start_ns >= end_ns:
        return "window_unconfirmed"
    if min(end_ns, pend) - max(start_ns, pstart) < 10_000_000_000:
        return "window_unconfirmed"
    peer_stats = peer.get("stats")
    if not isinstance(peer_stats, dict) or any(type(peer_stats.get(key)) is not bool for key in ("hello_received", "ack_received")):
        return "window_unconfirmed"
    return "established" if (stats["hello_received"] and stats["ack_received"] and
                             peer_stats["hello_received"] and peer_stats["ack_received"]) else "not_established"


SYNTHETIC_PREFIX = b'VZ_SYNTHETIC_NON_KERNEL\n'


def wire_fixture(ctx, own_nonce, peer_nonce):
    intel, receiver = (own_nonce, peer_nonce) if ctx['role'] == 'intel' else (peer_nonce, own_nonce)
    body = json.dumps({'binding': '/'.join((ctx['run'], ctx['attempt'], ctx['sha'])),
                       'intel_nonce': intel.hex(), 'receiver_nonce': receiver.hex()}, separators=(',', ':')).encode()
    return 'vz-synthetic-' + hashlib.sha256(body).hexdigest(), SYNTHETIC_PREFIX + body + b'\n' + b'0123456789abcdef' * 70


def _wire_packet(sock, peer, packet, block, deadline):
    for _ in range(240):
        if time.monotonic() >= deadline:
            break
        sock.sendto(packet, peer)
        until = min(deadline, time.monotonic() + .25)
        for _ in range(256):
            remaining = until - time.monotonic()
            if remaining <= 0 or not select.select([sock], [], [], remaining)[0]:
                break
            data, address = sock.recvfrom(4096)
            if address == peer and wire.decode_ack(data) == block:
                return
    raise TimeoutError('wire_ack_unconfirmed')


def wire_exchange(sock, peer, role, filename, data, commit, *, seconds=60):
    deadline = time.monotonic() + seconds
    previous = sock.gettimeout()
    sock.settimeout(.25)
    try:
        if role == 'intel':
            _wire_packet(sock, peer, wire.encode_wrq(filename), 0, deadline)
            block = 1
            for offset in range(0, len(data), 512):
                _wire_packet(sock, peer, wire.encode_data(block, data[offset:offset + 512]), block, deadline)
                block += 1
            _wire_packet(sock, peer, wire.encode_eof(block), block, deadline)
        elif role == 'receiver' and callable(commit):
            receiver = wire.Receiver(filename, SYNTHETIC_PREFIX)
            committed = False
            for _ in range(256):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not select.select([sock], [], [], min(.25, remaining))[0]:
                    continue
                packet, address = sock.recvfrom(4096)
                if address != peer or packet.startswith(b'KDP1'):
                    continue
                reply = receiver.receive(packet)
                if receiver.state == 'failed':
                    raise ValueError('wire_packet_rejected')
                if receiver.state == 'complete' and not committed:
                    if receiver.data != data or commit(receiver.data) is not True:
                        raise ValueError('wire_commit_unconfirmed')
                    committed = True
                    deadline = min(deadline, time.monotonic() + 1)
                if reply is not None:
                    sock.sendto(reply, peer)
            if not committed:
                raise TimeoutError('wire_transfer_incomplete')
        else:
            raise ValueError('wire_role_invalid')
        return {'status': 'complete', 'scope': 'synthetic_crashdump_udp_only', 'bytes': len(data),
                'sha256': hashlib.sha256(data).hexdigest(), 'filename_sha256': hashlib.sha256(filename.encode()).hexdigest()}
    finally:
        sock.settimeout(previous)


def wire_fact(value):
    if (not isinstance(value, dict) or set(value) != {'status', 'scope', 'bytes', 'sha256', 'filename_sha256'} or
            value['status'] != 'complete' or value['scope'] != 'synthetic_crashdump_udp_only' or
            type(value['bytes']) is not int or not 0 < value['bytes'] <= 12288 or
            any(not isinstance(value[key], str) or not re.fullmatch(r'[0-9a-f]{64}', value[key]) for key in ('sha256', 'filename_sha256'))):
        raise ValueError('wire_fact_invalid')
    return dict(value)


def wire_envelope(value, fingerprint):
    if (not isinstance(value, dict) or set(value) != {'ciphertext', 'cipher_sha256', 'cert_fingerprint'} or
            value['cert_fingerprint'] != fingerprint or not isinstance(value['ciphertext'], str) or
            not 0 < len(value['ciphertext']) <= 58000):
        raise ValueError('wire_envelope_invalid')
    encrypted = base64.b64decode(value['ciphertext'], validate=True)
    if hashlib.sha256(encrypted).hexdigest() != value['cipher_sha256']:
        raise ValueError('wire_envelope_invalid')
    return dict(value)


def wire_sources(value):
    if (not isinstance(value, dict) or set(value) != {'preflight_sha256', 'codec_sha256', 'reports_sha256'} or
            any(not isinstance(item, str) or not re.fullmatch(r'[0-9a-f]{64}', item) for item in value.values())):
        raise ValueError('wire_source_invalid')
    return dict(value)


def wire_pair_matches(state, peer):
    try:
        if {state.get('role'), peer.get('role')} != {'intel', 'receiver'}:
            return False
        fingerprint = state.get('wire_cert_fingerprint')
        if (not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint) or
                peer.get('wire_cert_fingerprint') != fingerprint or
                wire_sources(state.get('wire_sources')) != wire_sources(peer.get('wire_sources')) or
                wire_fact(state.get('wire_transfer')) != wire_fact(peer.get('wire_transfer'))):
            return False
        receiver = state if state['role'] == 'receiver' else peer
        wire_envelope(receiver.get('wire_envelope'), fingerprint)
        return True
    except (ValueError, TypeError, KeyError):
        return False


def run(ctx, token):
    own, other = ctx["role"], "receiver" if ctx["role"] == "intel" else "intel"
    cert = os.environ.pop("KDP_REPORT_CERT", "").encode()
    fingerprint = reports.cert_fingerprint(cert) if ctx["port_mode"] == "crashdump-wire" else None
    check = api("POST", "/check-runs", token, {"name": "KDP UDP " + own + " " + ctx["run"],
                "head_sha": ctx["sha"], "external_id": binding(ctx, own), "status": "in_progress",
                "output": {"title": "UDP path preflight", "summary": json.dumps({"phase": "init", "role": own,
                    "binding": binding(ctx, own), "port_mode": ctx["port_mode"]})}})
    if not check_identity(check, ctx, own):
        raise ValueError("own check identity")
    check_id = check["id"]
    sock = None
    state = {"phase": "result", "role": own, "binding": binding(ctx, own),
             "port_mode": ctx["port_mode"], "result": "unsupported"}
    try:
        nonce = os.urandom(16)
        peer = None
        if ctx["port_mode"] in ("kernel-source", "crashdump-wire") and own == "intel":
            peer = wait_peer(ctx, token, other, nonce.hex())
            if peer is None:
                state.update({"result": "window_unconfirmed", "reason": "peer_not_ready"})
                return state
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", bind_port(ctx, peer)))
            state["local_port"] = sock.getsockname()[1]
            candidates = socket.getaddrinfo("stun.cloudflare.com", 3478, socket.AF_INET, socket.SOCK_DGRAM)
            servers = [(item[4][0], 3478) for item in candidates if public_endpoint(item[4][0], 3478)]
            if not servers:
                raise ValueError("no public STUN endpoint")
            endpoint, mappings = audit_mappings(sock, servers)
            state["mapping_samples"] = mappings
            if endpoint is None:
                raise ValueError("STUN endpoint unavailable")
        except (OSError, ValueError):
            state["reason"] = "stun_or_bind_unavailable"
            return state
        state = {"phase": "ready", "role": own, "binding": binding(ctx, own), "nonce": nonce.hex(),
                 "port_mode": ctx["port_mode"], "local_port": state["local_port"],
                 "endpoint": {"ip": endpoint[0], "port": endpoint[1]}, "mapping_samples": mappings}
        if peer is not None:
            state["peer_public_port"] = peer["endpoint"]["port"]
        update(check_id, token, state)
        print(json.dumps({"event": "udp_ready", "role": own, "nonce": nonce.hex(), "endpoint": state["endpoint"],
                          "port_mode": ctx["port_mode"], "local_port": state["local_port"]}), flush=True)
        if peer is None:
            peer = wait_peer(ctx, token, other, nonce.hex())
        if peer is None:
            state.update({"phase": "result", "result": "window_unconfirmed", "reason": "peer_not_ready"})
            return state
        remote, nonce_text = peer["endpoint"], peer["nonce"]
        address, peer_nonce = peer_endpoint(peer, nonce.hex())
        state["peer_public_port"] = address[1]
        state.update({"phase": "probing", "result": "window_unconfirmed", "reason": "probe_incomplete"})
        update(check_id, token, state)
        start_ns = time.time_ns()
        stats = exchange(sock, address, nonce, peer_nonce, 30)
        end_ns = time.time_ns()
        state.update({"phase": "probing", "result": "pending", "start_ns": start_ns, "end_ns": end_ns,
                      "window_clock": "utc_clock_skew_unmeasured", "scope": "userspace_udp_only", "stats": stats})
        if ctx['port_mode'] == 'crashdump-wire':
            if not stats['hello_received'] or not stats['ack_received']:
                raise ValueError('wire_path_unconfirmed')
            filename, payload = wire_fixture(ctx, nonce, peer_nonce)
            state['scope'] = 'synthetic_crashdump_udp_only'
            state['wire_cert_fingerprint'] = fingerprint
            state['wire_sources'] = {key: hashlib.sha256(Path(path).read_bytes()).hexdigest() for key, path in
                (('preflight_sha256', __file__), ('codec_sha256', wire.__file__), ('reports_sha256', reports.__file__))}
            def commit(value):
                state['wire_transfer'] = wire_fact({'status': 'complete', 'scope': 'synthetic_crashdump_udp_only',
                    'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                    'filename_sha256': hashlib.sha256(filename.encode()).hexdigest()})
                state['wire_envelope'] = reports.encrypt_bundle(cert, {'kind': 'synthetic_crashdump',
                    'binding': binding(ctx, own), 'nonce': nonce.hex(), 'peer_nonce': peer_nonce.hex(),
                    'sources': state['wire_sources'], 'payload_sha256': hashlib.sha256(value).hexdigest()}, value)
                wire_envelope(state['wire_envelope'], fingerprint)
                if len(json.dumps(state).encode()) > 60000:
                    raise ValueError('wire_public_result_oversized')
                update(check_id, token, state)
                saved = api('GET', '/check-runs/' + str(check_id), token)
                if (not check_identity(saved, ctx, own) or saved.get('status') != 'in_progress' or
                        saved.get('output', {}).get('summary') != json.dumps(state, separators=(',', ':'))):
                    raise ValueError('wire_public_commit_unconfirmed')
                return True
            state['wire_transfer'] = wire_exchange(sock, address, own, filename, payload, commit if own == 'receiver' else None)
        state['phase'] = 'result'
        update(check_id, token, state)
        peer_last = None
        wait_until = time.monotonic() + 35
        while time.monotonic() < wait_until:
            candidate = peer_check(ctx, token, other)
            if candidate and candidate.get("phase") == "result":
                peer_last = candidate
                break
            time.sleep(1)
        if not peer_last or peer_last.get("nonce") != nonce_text or peer_last.get("endpoint") != remote:
            state.update({"result": "window_unconfirmed", "reason": "peer_metadata_missing_or_changed"})
        elif not port_pair_matches(state, peer_last):
            state.update({"result": "window_unconfirmed", "reason": "port_pair_mismatch"})
        else:
            state["result"] = window_outcome(stats, start_ns, end_ns, peer_last)
            if ctx['port_mode'] == 'crashdump-wire' and not wire_pair_matches(state, peer_last):
                state['result'] = 'window_unconfirmed'
            state.pop("reason", None)
        return state
    finally:
        if sock is not None:
            sock.close()
        state["phase"] = "result"
        if state.get("result") in (None, "pending"):
            state.update({"result": "window_unconfirmed", "reason": "probe_incomplete"})
        state["check_update"] = "not_confirmed"
        persist_state(state)
        update(check_id, token, state, "success" if state.get("result") == "established" else "neutral")
        state["check_update"] = "confirmed"
        persist_state(state)
        print(json.dumps({"event": "udp_result", "role": own, "result": state.get("result"),
                          "reason": state.get("reason"), "window_clock": state.get("window_clock"),
                          "port_mode": ctx["port_mode"], "local_port": state.get("local_port"),
                          "peer_public_port": state.get("peer_public_port"),
                          "scope": state.get('scope', 'userspace_udp_only'), "stats": state.get("stats")}), flush=True)


def sanitize_state(state):
    result = {"phase": "result", "scope": "userspace_udp_only"}
    if state.get('port_mode') == 'crashdump-wire':
        result['scope'] = 'synthetic_crashdump_udp_only'
        try:
            result['wire_transfer'] = wire_fact(state.get('wire_transfer'))
            fingerprint = state.get('wire_cert_fingerprint')
            if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
                raise ValueError('wire_certificate_invalid')
            result['wire_cert_fingerprint'] = fingerprint
            result['wire_sources'] = wire_sources(state.get('wire_sources'))
            if state.get('role') == 'receiver':
                result['wire_envelope'] = wire_envelope(state.get('wire_envelope'), fingerprint)
        except (ValueError, TypeError):
            result.pop('wire_transfer', None)
    if state.get("role") in ("intel", "receiver"):
        result["role"] = state["role"]
    if state.get("port_mode") in ("symmetric", "kernel-source", "crashdump-wire"):
        result["port_mode"] = state["port_mode"]
    for key in ("local_port", "peer_public_port"):
        if type(state.get(key)) is int and 0 < state[key] < 65536:
            result[key] = state[key]
    result["result"] = state.get("result") if state.get("result") in ("unsupported", "window_unconfirmed", "not_established", "established") else "unsupported"
    if state.get('port_mode') == 'crashdump-wire' and 'wire_transfer' not in result:
        result['result'] = 'window_unconfirmed'
    if state.get("reason") in ("preflight_failed", "stun_or_bind_unavailable", "peer_not_ready", "probe_incomplete", "peer_metadata_missing_or_changed", "port_pair_mismatch"):
        result["reason"] = state["reason"]
    nonce = state.get("nonce")
    if isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce):
        result["nonce"] = nonce
    endpoint = state.get("endpoint")
    if isinstance(endpoint, dict) and public_endpoint(endpoint.get("ip", ""), endpoint.get("port")):
        result["endpoint"] = {"ip": endpoint["ip"], "port": endpoint["port"]}
    for key in ("start_ns", "end_ns"):
        if type(state.get(key)) is int and state[key] > 0:
            result[key] = state[key]
    if state.get("check_update") in ("not_confirmed", "confirmed"):
        result["check_update"] = state["check_update"]
    if state.get("window_clock") == "utc_clock_skew_unmeasured":
        result["window_clock"] = state["window_clock"]
    stats = state.get("stats")
    if (isinstance(stats, dict) and type(stats.get("hello_received")) is bool and
            type(stats.get("ack_received")) is bool and type(stats.get("sent")) is int and 0 <= stats["sent"] <= 280):
        result["stats"] = {key: stats[key] for key in ("hello_received", "ack_received", "sent")}
        count, ports = stats.get("valid_peer_port_mismatches"), stats.get("other_peer_ports")
        if (type(count) is int and 0 <= count <= 1_000_000 and isinstance(ports, list) and len(ports) <= 8
                and all(type(port) is int and 0 < port < 65536 for port in ports)):
            result["stats"].update({"valid_peer_port_mismatches": count, "other_peer_ports": ports})
    samples = state.get("mapping_samples")
    if isinstance(samples, list) and len(samples) <= 3:
        result["mapping_samples"] = []
        for sample in samples:
            if not isinstance(sample, dict) or not public_endpoint(sample.get("server_ip", ""), 3478):
                continue
            if sample.get("state") == "observed" and public_endpoint(sample.get("ip", ""), sample.get("port")):
                result["mapping_samples"].append({key: sample[key] for key in ("server_ip", "state", "ip", "port")})
            elif sample.get("state") == "unavailable":
                result["mapping_samples"].append({"server_ip": sample["server_ip"], "state": "unavailable"})
    return result


def persist_state(state):
    global artifact_written, artifact_failed
    runner_temp = os.environ.get("RUNNER_TEMP", "")
    if not runner_temp or not Path(runner_temp).is_dir():
        return
    temporary = None
    try:
        directory = Path(runner_temp) / "debug"
        directory.mkdir(parents=True, exist_ok=True)
        temporary = directory / (".kdp-udp-preflight-" + str(os.getpid()) + ".tmp")
        temporary.write_text(json.dumps(sanitize_state(state), indent=2) + "\n")
        os.replace(temporary, directory / "kdp-udp-preflight.json")
        artifact_written = True
    except OSError:
        artifact_failed = True
        print(json.dumps({"event": "udp_artifact_error", "status": "unsupported"}), flush=True)
        if temporary:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def main():
    state = {"result": "unsupported", "reason": "preflight_failed"}
    exit_code = 1
    try:
        ctx = validate_context()
        state["role"] = ctx["role"]
        state["port_mode"] = ctx["port_mode"]
        token = os.environ.pop("GITHUB_TOKEN", "")
        if not token:
            raise ValueError("token missing")
        state = run(ctx, token)
        exit_code = 0
    except (OSError, ValueError, TypeError, AttributeError, KeyError, subprocess.SubprocessError, urllib.error.URLError):
        print(json.dumps({"event": "udp_preflight_error", "status": "unsupported"}), flush=True)
    if not artifact_written:
        persist_state(state)
    if artifact_failed:
        exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
