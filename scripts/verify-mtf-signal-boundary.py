#!/usr/bin/env python3
"""Observe an owned MTF child before and after its bounded termination."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("mtf", Path(__file__).with_name("verify-mtf-controls.py"))
mtf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mtf)
PHASE = "mtf-hlt-observe"


def decide_termination(milestones, returned, acknowledge, send_signal):
    if returned:
        return "returned"
    if milestones != ["stage2", "30", "60", "90"]:
        return "inconclusive"
    try:
        if not acknowledge():
            return "inconclusive"
        send_signal()
        return "signalled"
    except (OSError, ValueError, TypeError, KeyError):
        return "inconclusive"


def valid_stage2(record, identity):
    return (isinstance(identity, dict) and record.get("api") == "mtf_run_until"
            and record.get("edge") == "before" and record.get("phase") == PHASE
            and record.get("pid") == identity.get("owner_pid")
            and record.get("sourcehash") == identity.get("source_sha256")
            and record.get("arg1") == 2 and record.get("arg2") == 20000000)


def early_completion(records, accepted, exit_code, eof):
    stage2 = [r for r in records if r.get("api") == "mtf_run_until" and r.get("edge") == "return"
              and r.get("phase") == PHASE and r.get("arg1") == 2 and r.get("result") == 0]
    return ("returned_clean" if eof and exit_code == 0 and set(accepted) == {"mov", "hlt"}
            and len(stage2) == 1 and mtf.exact(records, "process_result", (0, 0, 1)) else "inconclusive_cleanup")


def observe_and_publish(state, drain, publish):
    drain()
    if state["returned"]:
        return False
    try:
        publish({"return_observed_before_request": False})
    finally:
        drain()
    return True


def release_allowed(now, deadline):
    return now < deadline


def read_ready_line(fd, timeout):
    deadline, pending = time.monotonic() + timeout, b""
    while b"\n" not in pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError("sibling_ready_timeout")
        chunk = os.read(fd, 2048)
        if not chunk:
            raise ValueError("sibling_ready_eof")
        pending += chunk
        if len(pending) > 8192:
            raise ValueError("sibling_ready_oversize")
    return pending.split(b"\n", 1)


def context_ok():
    return (os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "Code-Hex/vz-ci-test"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            and re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ATTEMPT", ""))
            and re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", ""))
            and os.environ.get("RUNNER_TEMP"))


def milestone(token, stage, identity, info):
    state = {"stage": stage, "scope": "control_plane_observation_only", "kernel_uuid": mtf.KERNEL_UUID,
             **identity, **info}
    number = mtf.checkpoint(state, PHASE, 1, token)
    mtf.emit({"event": "boundary_checkpoint_ack", "stage": stage, "check_id": number})
    return number


def heartbeat_child():
    try:
        data = json.loads(sys.stdin.readline(8192))
        token, identity = data["token"], data["identity"]
        if not context_ok() or not isinstance(token, str) or not token or not isinstance(identity, dict):
            return 2
        started = time.monotonic()
        milestone(token, "sibling-ready", identity, {"sibling_elapsed_ms": 0})
        for i in range(1, 16):
            deadline = started + 10 * i
            while time.monotonic() < deadline:
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            if time.monotonic() > started + 150:
                break
            try:
                milestone(token, "sibling-" + str(i), identity,
                          {"sibling_elapsed_ms": int((time.monotonic() - started) * 1000)})
            except (OSError, ValueError, TypeError, KeyError):
                continue
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        return 1


def run(binary, token, directory, source_sha):
    env = dict(os.environ)
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    child = subprocess.Popen([str(binary), PHASE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True, env=env, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    records, pending, accepted, milestones = [], b"", {}, []
    identity, observed, returned, eof, invalid = None, None, False, False, False
    stage2_mach_ns = None
    attempted = set()
    setup_deadline = time.monotonic() + 45
    sibling, sibling_started, sibling_pending = None, None, b""
    next_heartbeat = time.monotonic() + 2
    rawpath = directory / "mtf-signal-boundary.jsonl"
    with rawpath.open("wb") as raw:
        def take_input(wait):
            nonlocal pending, returned, eof, invalid, identity, observed, sibling, sibling_started, sibling_pending, stage2_mach_ns
            for key, _ in selector.select(wait):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    eof = True
                    return
                raw.write(chunk)
                raw.flush()
                pending += chunk
                if len(pending) > 131072:
                    invalid = True
                    return
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict) or len(line) > 900:
                            raise ValueError("invalid_record")
                        mtf.emit(record)
                        records.append(record)
                        if (record.get("api") == "mtf_run_until" and record.get("edge") == "return"
                                and record.get("arg1") == 2):
                            returned = True
                        if record.get("api") in ("mtf_mov_checkpoint_ready", "mtf_checkpoint_ready") and record.get("edge") == "fact":
                            state = mtf.checkpoint_state(records, set(accepted))
                            ident = (record.get("pid"), record.get("sourcehash"))
                            owner = mtf.events(records, "owner_thread_id")
                            relevant = [r for r in records if str(r.get("api", "")).startswith("mtf_")]
                            if (ident[0] != child.pid or not isinstance(ident[1], str)
                                    or ident[1] != source_sha
                                    or any((r.get("pid"), r.get("sourcehash")) != ident for r in relevant)
                                    or record.get("phase") != PHASE
                                    or len(owner) != 1 or owner[0].get("result") != 0
                                    or (owner[0].get("pid"), owner[0].get("sourcehash")) != ident
                                    or type(owner[0].get("arg0")) is not int or owner[0]["arg0"] <= 0):
                                raise ValueError("identity")
                            identity = {"owner_pid": ident[0], "source_sha256": ident[1], "owner_tid": owner[0]["arg0"]}
                            state.update(identity, kernel_uuid=mtf.KERNEL_UUID)
                            accepted[state["stage"]] = mtf.checkpoint(state, PHASE, 1, token)
                            mtf.emit({"event": "checkpoint_ack", "stage": state["stage"], "check_id": accepted[state["stage"]]})
                            if state["stage"] == "mov":
                                sibling_started = time.monotonic()
                                sibling = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--heartbeat-child"],
                                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                           stderr=subprocess.DEVNULL, env=env, start_new_session=True, bufsize=0)
                                sibling.stdin.write((json.dumps({"token": token, "identity": identity}) + "\n").encode())
                                sibling.stdin.close()
                                ready_line, sibling_pending = read_ready_line(sibling.stdout.fileno(), 22)
                                response = json.loads(ready_line)
                                if (response.get("event") != "boundary_checkpoint_ack"
                                        or response.get("stage") != "sibling-ready"
                                        or type(response.get("check_id")) is not int):
                                    raise ValueError("sibling_not_ready")
                                mtf.emit({"event": "sibling_ready", "check_id": response["check_id"]})
                                if not release_allowed(time.monotonic(), setup_deadline):
                                    raise ValueError("setup_deadline")
                            child.stdin.write(b"G")
                            child.stdin.flush()
                        if (record.get("api") == "mtf_run_until" and record.get("edge") == "before"
                                and record.get("arg1") == 2):
                            if (not valid_stage2(record, identity) or set(accepted) != {"mov"}
                                    or observed is not None or sibling_started is None):
                                raise ValueError("stage2_order")
                            stage2_mach_ns = record.get("monotonic_ns")
                            if type(stage2_mach_ns) is not int or stage2_mach_ns <= 0:
                                raise ValueError("stage2_timestamp")
                            observed = time.monotonic()
                    except (ValueError, OSError, TypeError, KeyError):
                        invalid = True
                        return

        def drained_observation(stage, info):
            state = {"returned": False}
            def drain():
                nonlocal invalid, returned
                for _ in range(64):
                    if eof or invalid or not selector.select(0):
                        break
                    take_input(0)
                else:
                    invalid = True
                if child.poll() is not None:
                    returned = True
                state["returned"] = returned or invalid or eof
            def publish(observation):
                milestone(token, stage, identity, {**info, **observation,
                                                   "child_poll_running_before_request": child.poll() is None,
                                                   "stage2_before_mach_ns": stage2_mach_ns})
            return observe_and_publish(state, drain, publish)

        while not invalid and not eof and not returned:
            now = time.monotonic()
            if observed is None and now >= setup_deadline:
                break
            if observed is not None:
                elapsed = now - observed
                for seconds in (0, 30, 60, 90):
                    if elapsed >= seconds and seconds not in attempted:
                        attempted.add(seconds)
                        stage = "stage2" if seconds == 0 else str(seconds)
                        try:
                            if drained_observation(stage, {"elapsed_ms": int((time.monotonic() - observed) * 1000)}):
                                milestones.append(stage)
                        except (OSError, ValueError, TypeError, KeyError):
                            mtf.emit({"event": "boundary_checkpoint_unavailable", "stage": stage})
                        if returned or invalid or eof:
                            break
                if elapsed >= 90:
                    break
            if now >= next_heartbeat:
                mtf.emit({"event": "boundary_parent_heartbeat", "return_observed": returned})
                next_heartbeat = now + 2
            if not returned and not invalid and not eof:
                take_input(0.2)

        if returned or eof:
            drain_deadline = time.monotonic() + 30
            while not eof and not invalid and time.monotonic() < drain_deadline:
                take_input(0.2)
            code = None
            if eof:
                try:
                    code = child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            result = early_completion(records, accepted, code, eof and not invalid and not pending)
        elif invalid or observed is None:
            result = "inconclusive"
        else:
            def acknowledge():
                if not drained_observation("pre-signal", {"elapsed_ms": int((time.monotonic() - observed) * 1000)}):
                    return False
                return (not returned and not invalid and not eof and sibling is not None
                        and sibling.poll() is None and time.monotonic() - sibling_started <= 105)

            def terminate():
                mtf.emit({"event": "signal_begin", "signal": "SIGKILL", "owner_pid": child.pid,
                          "monotonic_ns": time.monotonic_ns()})
                os.killpg(child.pid, signal.SIGKILL)
                mtf.emit({"event": "signal_return", "owner_pid": child.pid,
                          "monotonic_ns": time.monotonic_ns()})

            result = decide_termination(milestones, returned, acknowledge, terminate)
            if result != "signalled" and (returned or eof):
                drain_deadline = time.monotonic() + 30
                while not eof and not invalid and time.monotonic() < drain_deadline:
                    take_input(0.2)
                code = None
                if eof:
                    try:
                        code = child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
                result = early_completion(records, accepted, code, eof and not invalid and not pending)
            if result == "signalled":
                try:
                    milestone(token, "signal-return", identity,
                              {"elapsed_ms": int((time.monotonic() - observed) * 1000)})
                except (OSError, ValueError, TypeError, KeyError):
                    mtf.emit({"event": "signal_return_checkpoint_unavailable"})
                try:
                    code = child.wait(timeout=2)
                    mtf.emit({"event": "child_wait_return", "exit": code})
                except subprocess.TimeoutExpired:
                    mtf.emit({"event": "child_wait_timeout"})
                post_until = time.monotonic() + 35
                while time.monotonic() < post_until:
                    mtf.emit({"event": "post_signal_parent_heartbeat"})
                    time.sleep(min(5, max(0, post_until - time.monotonic())))
    selector.close()
    mtf.emit({"event": "boundary_result", "result": result, "milestones": milestones,
              "sibling_pid": sibling.pid if sibling else None})
    return 0 if result in ("signalled", "returned_clean") else 1


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--heartbeat-child":
        return heartbeat_child()
    if len(sys.argv) != 2 or not context_ok():
        mtf.emit({"event": "error", "reason": "invalid_context"})
        return 2
    binary = Path(sys.argv[1]).resolve()
    token = os.environ.pop("GITHUB_TOKEN", "")
    try:
        uuid = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.uuid"], text=True, timeout=5).strip().upper()
    except (OSError, subprocess.SubprocessError):
        uuid = ""
    if not binary.is_file() or not os.access(binary, os.X_OK) or not token or uuid != mtf.KERNEL_UUID:
        mtf.emit({"event": "error", "reason": "invalid_input"})
        return 2
    directory = Path(os.environ["RUNNER_TEMP"]) / "debug" / "mtf-signal-boundary"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        source = Path(__file__).resolve().parent.parent / "probes" / "hypervisor.c"
        source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        return run(binary, token, directory, source_sha)
    except (OSError, ValueError, TypeError, KeyError):
        mtf.emit({"event": "boundary_result", "result": "inconclusive"})
        return 1


if __name__ == "__main__":
    sys.exit(main())
