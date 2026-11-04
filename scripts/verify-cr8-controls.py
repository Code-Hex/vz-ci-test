#!/usr/bin/env python3
"""Run public Hypervisor API functional controls without DTrace."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

PHASES = {
    "cpuid": ("armed-protected32-paging-cpuid-cr8-kernelmarkers", "sentinel_cpuid_verified", 10, 263, 2, None),
    "hlt": ("armed-protected32-paging-hlt-cr8-kernelmarkers", "sentinel_hlt_verified", 12, 263, 1, None),
    "timer-spin": ("protected32-paging-spin-cr8-timer", "sentinel_spin_verified", 52, 263, 0, 0),
    "timer-hlt": ("protected32-paging-hlt-cr8-timer", "sentinel_hlt_timer_verified", 52, 264, 0, 1),
}
MODES = {"cr8": ("cpuid", "hlt"), "timer": ("timer-spin", "timer-hlt")}
GATES = {"run_ready", "run_return_ready", "cleanup_ready"}


def is_gate(record):
    return record.get("edge") == "fact" and record.get("api") in GATES and record.get("result") == 0


def classify(phase, records, exit_code, timed_out):
    if timed_out:
        return "timeout"
    facts = [r for r in records if r.get("edge") == "fact"]
    process = [r for r in facts if r.get("api") == "process_result"]
    if len(process) != 1:
        return "failure"
    end = process[0]
    observation = [r for r in facts if r.get("api") == "guest_observation"]
    _, verified_name, reason, rip, length, activity = PHASES[phase]
    verified = [r for r in facts if r.get("api") == verified_name]
    state = [r for r in facts if r.get("api") == "timer_guest_state"]
    phase_result = [r for r in facts if r.get("api") == "phase_result"]
    activity_valid = (activity is None or
                      (len(state) == 1 and state[0].get("result") == 0 and
                       tuple(state[0].get(f"arg{i}") for i in range(3)) == (reason, rip, activity) and
                       len(phase_result) == 1 and phase_result[0].get("result") == 0 and
                       phase_result[0].get("arg1") == 1))
    if (exit_code == 0 and end.get("result") == 0 and end.get("arg0") == 0
            and end.get("arg1") == 0 and end.get("arg2") == 1
            and len(observation) == 1 and observation[0].get("result") == 0
            and tuple(observation[0].get(f"arg{i}") for i in range(3)) == (165, rip, length)
            and len(verified) == 1 and verified[0].get("result") == 0
            and tuple(verified[0].get(f"arg{i}") for i in range(3)) == (reason, rip, length)
            and activity_valid):
        return "success"
    failed = [r for r in facts if r.get("api") == "guest_not_established"]
    if (exit_code == 77 and end.get("result") == 77 and end.get("arg0") == 77
            and end.get("arg1") == 0 and end.get("arg2") == 0
            and len(failed) == 1 and failed[0].get("result") == 77
            and failed[0].get("arg0") == 1):
        return "retry"
    return "failure"


def emit(record):
    print(json.dumps(record, separators=(",", ":")), flush=True)


def run_attempt(binary, directory, phase, attempt):
    name = phase if phase.startswith("timer-") else f"cr8-{phase}"
    path = directory / f"{name}-{attempt}.jsonl"
    command = [str(binary), PHASES[phase][0]]
    emit({"event": "harness_start", "phase": phase, "attempt": attempt, "raw": str(path)})
    records, pending = [], b""
    timed_out = False
    with path.open("wb") as raw:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 20
        heartbeat = time.monotonic() + 2
        eof = False
        while not eof:
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            if now >= heartbeat:
                emit({"event": "harness_heartbeat", "phase": phase, "attempt": attempt, "elapsed_seconds": round(now - (deadline - 20), 3)})
                heartbeat = now + 2
            for key, _ in selector.select(min(deadline - now, heartbeat - now)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    eof = True
                    break
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    try:
                        record = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        record = {"event": "harness_child_output", "text": line.decode("utf-8", "replace")}
                    encoded = json.dumps(record, separators=(",", ":"))
                    raw.write(encoded.encode() + b"\n")
                    raw.flush()
                    print(encoded, flush=True)
                    if isinstance(record, dict):
                        records.append(record)
                        if is_gate(record):
                            try:
                                child.stdin.write(b"G")
                                child.stdin.flush()
                            except BrokenPipeError:
                                pass
        selector.close()
        if pending:
            record = {"event": "harness_child_output", "text": pending.decode("utf-8", "replace"), "partial": True}
            encoded = json.dumps(record, separators=(",", ":"))
            raw.write(encoded.encode() + b"\n")
            raw.flush()
            print(encoded, flush=True)
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
        child.stdin.close()
        child.stdout.close()
    result = classify(phase, records, exit_code, timed_out)
    emit({"event": "harness_attempt_result", "phase": phase, "attempt": attempt, "exit": exit_code, "result": result})
    return {"phase": phase, "attempt": attempt, "exit": exit_code, "result": result, "raw": str(path)}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "timer") or not os.environ.get("RUNNER_TEMP"):
        print("usage: RUNNER_TEMP=DIR verify-cr8-controls.py SIGNED_HYPERVISOR_BINARY [timer]", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        print("signed hypervisor binary must be an executable file", file=sys.stderr)
        return 2
    mode = sys.argv[2] if len(sys.argv) == 3 else "cr8"
    directory = Path(os.environ["RUNNER_TEMP"]) / "debug" / f"{mode}-controls"
    directory.mkdir(parents=True, exist_ok=True)
    summary = {"event": "harness_summary", "result": "failure", "attempts": []}
    try:
        for phase in MODES[mode]:
            for attempt in range(1, 4):
                result = run_attempt(binary, directory, phase, attempt)
                summary["attempts"].append(result)
                if result["result"] != "retry":
                    break
            if result["result"] != "success":
                break
        else:
            summary["result"] = "success"
    except (OSError, ValueError) as error:
        summary["error"] = str(error)
    (directory / f"{mode}-controls-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    emit(summary)
    return 0 if summary["result"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
