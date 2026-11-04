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

PHASES = ("cpuid", "hlt")
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
    verified = [r for r in facts if r.get("api") == f"sentinel_{phase}_verified"]
    expected = (10, 2) if phase == "cpuid" else (12, 1)
    if (exit_code == 0 and end.get("result") == 0 and end.get("arg0") == 0
            and end.get("arg1") == 0 and end.get("arg2") == 1
            and len(observation) == 1 and observation[0].get("result") == 0
            and tuple(observation[0].get(f"arg{i}") for i in range(3)) == (165, 263, expected[1])
            and len(verified) == 1 and verified[0].get("result") == 0
            and tuple(verified[0].get(f"arg{i}") for i in range(3)) == (expected[0], 263, expected[1])):
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
    path = directory / f"cr8-{phase}-{attempt}.jsonl"
    command = [str(binary), f"armed-protected32-paging-{phase}-cr8-kernelmarkers"]
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
    if len(sys.argv) != 2 or not os.environ.get("RUNNER_TEMP"):
        print("usage: RUNNER_TEMP=DIR verify-cr8-controls.py SIGNED_HYPERVISOR_BINARY", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        print("signed hypervisor binary must be an executable file", file=sys.stderr)
        return 2
    directory = Path(os.environ["RUNNER_TEMP"]) / "debug" / "cr8-controls"
    directory.mkdir(parents=True, exist_ok=True)
    summary = {"event": "harness_summary", "result": "failure", "attempts": []}
    try:
        for phase in PHASES:
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
    (directory / "cr8-controls-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    emit(summary)
    return 0 if summary["result"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
