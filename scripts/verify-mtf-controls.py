#!/usr/bin/env python3
"""Capture synthetic guest state before resuming the MTF experiment."""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import urllib.request

FIELDS = {0x681e, 0x681c, 0x6820, 0x4826, 0x4824, 0x4016, 0x4000, 0x4002, 0x482e, 0x400c}
MOV_PHASES = {"mtf-mov", "mtf-forever-mov"}
OBSERVE_PHASES = {"mtf-hlt-observe", "mtf-forever-hlt-observe"}
PHASES = MOV_PHASES | OBSERVE_PHASES | {"mtf-hlt-resume", "mtf-nop-observe"}
API = "https://api.github.com/repos/Code-Hex/vz-ci-test/check-runs"
KERNEL_UUID = "87453B1D-A163-31FA-B33B-0FB4BE78E6E8"


def events(records, name):
    return [r for r in records if r.get("api") == name and r.get("edge") == "fact"]


def args(record):
    return tuple(record.get("arg" + str(i)) for i in range(3))


def exact(records, name, expected):
    values = events(records, name)
    return len(values) == 1 and values[0].get("result") == 0 and args(values[0]) == expected


def valid_snapshot(records):
    exits = events(records, "mtf_exit")
    tags = events(records, "mtf_exit_tag")
    if (len(exits) != 2 or [args(r) for r in exits] != [(37, 263, 0), (37, 264, 1)]
            or len(tags) != 2 or [args(r) for r in tags] != [(1, 165, 0), (2, 165, 0)]
            or any(r.get("result") != 0 for r in exits + tags)
            or not exact(records, "mtf_snapshot_complete", (2, 264, 1))
            or not exact(records, "mtf_hlt_verified", (37, 264, 1))):
        raise ValueError("snapshot_invalid")
    positions = [records.index(exits[0]), records.index(tags[0]), records.index(exits[1]),
                 records.index(tags[1]), records.index(events(records, "mtf_snapshot_complete")[0]),
                 records.index(events(records, "mtf_hlt_verified")[0])]
    if positions != sorted(set(positions)):
        raise ValueError("snapshot_order")
    def read(name, expected):
        found = {}
        for r in events(records, name):
            stage, key, value = args(r)
            if (r.get("result") != 0 or stage != 2 or type(key) is not int or key not in expected
                    or key in found or type(value) is not int or not 0 <= value < 2**64):
                raise ValueError("snapshot_invalid")
            found[key] = value
        if found.keys() != expected:
            raise ValueError("snapshot_invalid")
        return found
    vmcs = read("mtf_guest_vmcs", FIELDS)
    regs = read("mtf_guest_register", set(range(2, 18)))
    primary = vmcs[0x4002]
    if (vmcs[0x681e] != 264 or vmcs[0x4826] != 1
            or primary & (1 << 7) or primary & ((1 << 27) | (3 << 19)) != (1 << 27) | (3 << 19)):
        raise ValueError("snapshot_invalid")
    return {"scope": "synthetic_guest_not_host", "vmcs": {str(k): v for k, v in vmcs.items()},
            "registers": {str(k): v for k, v in regs.items()},
            "timer_saved_on_exit": bool(vmcs[0x400c] & (1 << 22))}


def checkpoint_state(records, accepted):
    if not records:
        raise ValueError("checkpoint_gate")
    gate = records[-1]
    if gate.get("edge") != "fact" or gate.get("result") != 0 or args(gate) != (71, 0, 0):
        raise ValueError("checkpoint_gate")
    if gate.get("api") == "mtf_mov_checkpoint_ready":
        exits, tags = events(records, "mtf_exit"), events(records, "mtf_exit_tag")
        if (accepted or len(events(records, "mtf_mov_checkpoint_ready")) != 1
                or len(exits) != 1 or len(tags) != 1 or exits[0].get("result") != 0
                or tags[0].get("result") != 0 or args(exits[0]) != (37, 263, 0)
                or args(tags[0]) != (1, 165, 0)
                or not records.index(exits[0]) < records.index(tags[0]) < len(records) - 1):
            raise ValueError("mov_invalid")
        return {"stage": "mov", "scope": "synthetic_guest_not_host",
                "exit_reason": 37, "rip": 263, "activity": 0, "tag": 165}
    if gate.get("api") == "mtf_checkpoint_ready":
        mov = events(records, "mtf_mov_checkpoint_ready")
        exits = events(records, "mtf_exit")
        if (accepted != {"mov"} or len(mov) != 1 or len(events(records, "mtf_checkpoint_ready")) != 1
                or len(exits) != 2 or not records.index(mov[0]) < records.index(exits[1])):
            raise ValueError("checkpoint_order")
        state = valid_snapshot(records)
        state["stage"] = "hlt"
        return state
    raise ValueError("checkpoint_gate")


def resume_verified(records):
    return (exact(records, "mtf_resume_state_equal", (264, 264, 1))
            and exact(records, "mtf_resume_exit", (52, 264, 1)))


def phase_success(phase, records, clean, checkpoints):
    if not clean:
        return False
    if phase in MOV_PHASES:
        return exact(records, "mtf_mov_verified", (37, 263, 165))
    if phase == "mtf-nop-observe":
        exits, tags = events(records, "mtf_exit"), events(records, "mtf_exit_tag")
        gates = events(records, "mtf_mov_checkpoint_ready")
        if (set(checkpoints) != {"mov"} or len(exits) != 2 or len(tags) != 2 or len(gates) != 1
                or any(r.get("result") != 0 for r in exits + tags + gates)
                or [args(r) for r in exits] != [(37, 263, 0), (37, 264, 0)]
                or [args(r) for r in tags] != [(1, 165, 0), (2, 165, 0)]
                or args(gates[0]) != (71, 0, 0)
                or not exact(records, "mtf_nop_verified", (37, 264, 0))):
            return False
        points = [records.index(exits[0]), records.index(tags[0]), records.index(gates[0]),
                  records.index(exits[1]), records.index(tags[1]), records.index(events(records, "mtf_nop_verified")[0])]
        return points == sorted(set(points))
    return (set(checkpoints) == {"mov", "hlt"} and
            (phase in OBSERVE_PHASES or (phase == "mtf-hlt-resume" and resume_verified(records))))


def attempt_classification(records, exit_code, timed_out):
    if timed_out:
        return "timeout"
    failed, end = events(records, "mtf_unexpected_exit"), events(records, "process_result")
    if (exit_code == 77 and len(failed) == len(end) == 1 and failed[0].get("result") == 77
            and failed[0].get("arg0") == 1 and failed[0].get("arg1") in (1, 2)
            and end[0].get("result") == 77 and args(end[0]) == (77, 0, 0)
            and not events(records, "mtf_checkpoint_ready")
            and not events(records, "mtf_mov_checkpoint_ready")):
        return "retry"
    return "failure"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect")


def request(method, url, token, body=None):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as response:
        return json.loads(response.read(65537))


def checkpoint(state, phase, number, token):
    run, attempt, sha = (os.environ[k] for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"))
    stage = state["stage"]
    name = "MTF " + stage + " " + phase + " " + run
    external = "/".join(("mtf", run, attempt, phase, str(number), stage))
    summary = json.dumps({"run": run, "attempt": attempt, "phase": phase, "state": state}, separators=(",", ":"))
    body = {"name": name, "head_sha": sha, "external_id": external, "status": "completed",
            "conclusion": "neutral", "output": {"title": "Synthetic guest MTF snapshot", "summary": summary}}
    created = request("POST", API, token, body)
    check_id = created.get("id")
    if type(check_id) is not int or check_id <= 0:
        raise ValueError("checkpoint_invalid")
    checked = request("GET", API + "/" + str(check_id), token)
    if (checked.get("id") != check_id or checked.get("name") != name
            or checked.get("external_id") != external or checked.get("head_sha") != sha
            or checked.get("status") != "completed" or checked.get("conclusion") != "neutral"
            or checked.get("app", {}).get("id") != 15368
            or checked.get("details_url") != "https://github.com/Code-Hex/vz-ci-test/runs/" + str(check_id)
            or checked.get("output", {}).get("summary") != summary):
        raise ValueError("checkpoint_invalid")
    return check_id


def emit(record):
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    if len(line.encode()) > 900:
        raise ValueError("oversize_output")
    print(line, flush=True)


def run_attempt(binary, directory, phase, number, token):
    records, pending, checkpoints = [], b"", {}
    timed_out, invalid = False, False
    path = directory / (phase + "-attempt" + str(number) + ".jsonl")
    env = dict(os.environ)
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    child = subprocess.Popen([str(binary), phase], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True, env=env, bufsize=0)
    deadline, heartbeat = time.monotonic() + 45, time.monotonic() + 2
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    with path.open("wb") as raw:
        eof = False
        while not eof:
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                break
            if now >= heartbeat:
                emit({"event": "heartbeat", "phase": phase, "attempt": number})
                heartbeat = now + 2
            for key, _ in selector.select(min(deadline - now, max(0, heartbeat - now))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    eof = True
                    break
                raw.write(chunk)
                raw.flush()
                pending += chunk
                if len(pending) > 131072:
                    invalid = True
                    break
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict) or len(line) > 900:
                            raise ValueError("child_output")
                        emit(record)
                        records.append(record)
                        if record.get("api") in ("mtf_mov_checkpoint_ready", "mtf_checkpoint_ready") and record.get("edge") == "fact":
                            if phase in MOV_PHASES:
                                raise ValueError("checkpoint_gate")
                            state = checkpoint_state(records, set(checkpoints))
                            state["kernel_uuid"] = KERNEL_UUID
                            identity = (record.get("pid"), record.get("sourcehash"))
                            relevant = [r for r in records if str(r.get("api", "")).startswith("mtf_")]
                            if (identity[0] != child.pid or not isinstance(identity[1], str)
                                    or not re.fullmatch(r"[0-9a-f]{64}", identity[1])
                                    or any((r.get("pid"), r.get("sourcehash")) != identity for r in relevant)):
                                raise ValueError("snapshot_identity")
                            owner = events(records, "owner_thread_id")
                            if (len(owner) != 1 or owner[0].get("result") != 0
                                    or (owner[0].get("pid"), owner[0].get("sourcehash")) != identity
                                    or type(owner[0].get("arg0")) is not int or owner[0]["arg0"] <= 0):
                                raise ValueError("snapshot_identity")
                            state["owner_pid"], state["source_sha256"] = identity
                            state["owner_tid"] = owner[0]["arg0"]
                            checkpoint_id = checkpoint(state, phase, number, token)
                            checkpoints[state["stage"]] = checkpoint_id
                            emit({"event": "checkpoint_ack", "check_id": checkpoint_id, "phase": phase, "stage": state["stage"]})
                            if time.monotonic() >= deadline:
                                timed_out = True
                                raise TimeoutError("checkpoint_deadline")
                            child.stdin.write(b"G")
                            child.stdin.flush()
                    except (ValueError, OSError, TypeError, KeyError):
                        invalid = True
                        break
                if invalid:
                    break
            if invalid:
                break
    if invalid or timed_out:
        try:
            child.stdin.close()
            os.killpg(child.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    try:
        exit_code = child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            exit_code = child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            exit_code = None
    selector.close()
    child.stdout.close()
    if not child.stdin.closed:
        child.stdin.close()
    result = attempt_classification(records, exit_code, timed_out)
    clean = exit_code == 0 and exact(records, "process_result", (0, 0, 1)) and not invalid and not pending
    if phase_success(phase, records, clean, checkpoints):
        result = "success"
    emit({"event": "attempt_result", "phase": phase, "attempt": number, "result": result,
          "exit": exit_code, "checkpoints": checkpoints})
    return result


def main():
    if (len(sys.argv) != 3 or sys.argv[2] not in PHASES or not os.environ.get("RUNNER_TEMP")
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "Code-Hex/vz-ci-test"
            or os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ATTEMPT", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", ""))):
        emit({"event": "error", "reason": "invalid_context"})
        return 2
    binary, phase = Path(sys.argv[1]).resolve(), sys.argv[2]
    kernel_uuid = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.uuid"], text=True, timeout=5).strip().upper()
    if kernel_uuid != KERNEL_UUID:
        emit({"event": "error", "reason": "kernel_uuid_mismatch"})
        return 2
    emit({"event": "kernel_identity", "kernel_uuid": kernel_uuid})
    token = os.environ.pop("GITHUB_TOKEN", "")
    if not binary.is_file() or not os.access(binary, os.X_OK) or (phase not in MOV_PHASES and not token):
        emit({"event": "error", "reason": "invalid_input"})
        return 2
    directory = Path(os.environ["RUNNER_TEMP"]) / "debug" / "mtf-controls"
    directory.mkdir(parents=True, exist_ok=True)
    for number in range(1, 4):
        result = run_attempt(binary, directory, phase, number, token)
        if result != "retry":
            return 0 if result == "success" else 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
