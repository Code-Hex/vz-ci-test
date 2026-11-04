#!/usr/bin/env python3
"""Same-run UDP/STUN path preflight; no KDP or kernel state is transmitted."""
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


def validate_context():
    ctx = {"run": os.getenv("GITHUB_RUN_ID", ""), "attempt": os.getenv("GITHUB_RUN_ATTEMPT", ""),
           "sha": os.getenv("GITHUB_SHA", ""), "role": os.getenv("KDP_ROLE", "")}
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
    if data.get("binding") != binding(ctx, role) or data.get("role") != role:
        raise ValueError("peer binding")
    return data


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


def run(ctx, token):
    own, other = ctx["role"], "receiver" if ctx["role"] == "intel" else "intel"
    check = api("POST", "/check-runs", token, {"name": "KDP UDP " + own + " " + ctx["run"],
                "head_sha": ctx["sha"], "external_id": binding(ctx, own), "status": "in_progress",
                "output": {"title": "UDP path preflight", "summary": json.dumps({"phase": "init", "role": own, "binding": binding(ctx, own)})}})
    if not check_identity(check, ctx, own):
        raise ValueError("own check identity")
    check_id = check["id"]
    sock = None
    state = {"phase": "result", "role": own, "binding": binding(ctx, own), "result": "unsupported"}
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 41139))
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
        nonce = os.urandom(16)
        state = {"phase": "ready", "role": own, "binding": binding(ctx, own), "nonce": nonce.hex(),
                 "endpoint": {"ip": endpoint[0], "port": endpoint[1]}, "mapping_samples": mappings}
        update(check_id, token, state)
        print(json.dumps({"event": "udp_ready", "role": own, "nonce": nonce.hex(), "endpoint": state["endpoint"]}), flush=True)
        peer = None
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            candidate = peer_check(ctx, token, other)
            if candidate and candidate.get("phase") in ("ready", "probing", "result"):
                peer = candidate
                break
            time.sleep(1)
        if not peer or peer.get("result") == "unsupported":
            state.update({"phase": "result", "result": "window_unconfirmed", "reason": "peer_not_ready"})
            return state
        remote = peer.get("endpoint", {})
        nonce_text = peer.get("nonce", "")
        if (not isinstance(remote, dict) or not public_endpoint(remote.get("ip", ""), remote.get("port")) or
                not isinstance(nonce_text, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce_text) or nonce_text == nonce.hex()):
            raise ValueError("peer metadata invalid")
        address = (remote["ip"], remote["port"])
        peer_nonce = bytes.fromhex(nonce_text)
        state.update({"phase": "probing", "result": "window_unconfirmed", "reason": "probe_incomplete"})
        update(check_id, token, state)
        start_ns = time.time_ns()
        stats = exchange(sock, address, nonce, peer_nonce, 30)
        end_ns = time.time_ns()
        state.update({"phase": "result", "result": "pending", "start_ns": start_ns, "end_ns": end_ns,
                      "window_clock": "utc_clock_skew_unmeasured", "scope": "userspace_udp_only", "stats": stats})
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
        else:
            state["result"] = window_outcome(stats, start_ns, end_ns, peer_last)
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
                          "scope": "userspace_udp_only", "stats": state.get("stats")}), flush=True)


def sanitize_state(state):
    result = {"phase": "result", "scope": "userspace_udp_only"}
    if state.get("role") in ("intel", "receiver"):
        result["role"] = state["role"]
    result["result"] = state.get("result") if state.get("result") in ("unsupported", "window_unconfirmed", "not_established", "established") else "unsupported"
    if state.get("reason") in ("preflight_failed", "stun_or_bind_unavailable", "peer_not_ready", "probe_incomplete", "peer_metadata_missing_or_changed"):
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
