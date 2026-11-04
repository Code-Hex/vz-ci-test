#!/usr/bin/env python3
"""Repeat the existing MOV-only control with a fresh process per attempt."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

spec = importlib.util.spec_from_file_location("mtf_controls", Path(__file__).with_name("verify-mtf-controls.py"))
mtf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mtf)


def run_rounds(run, save):
    for number in range(1, 11):
        attempts = []
        for attempt in range(1, 4):
            result = run(number, attempt)
            attempts.append(result)
            if result != "retry":
                break
        final = "retry_exhausted" if result == "retry" else result
        save({"round": number, "attempts": attempts, "result": final})
        if final != "success":
            return False
    return True


def main():
    if (len(sys.argv) != 2 or not os.environ.get("RUNNER_TEMP")
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "Code-Hex/vz-ci-test"
            or os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ATTEMPT", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", ""))):
        mtf.emit({"event": "error", "reason": "invalid_context"})
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        mtf.emit({"event": "error", "reason": "invalid_binary"})
        return 2
    try:
        uuid = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.uuid"], text=True, timeout=5).strip().upper()
        signature = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError):
        mtf.emit({"event": "error", "reason": "guard_failed"})
        return 2
    if uuid != mtf.KERNEL_UUID or signature.returncode != 0:
        mtf.emit({"event": "error", "reason": "guard_failed"})
        return 2
    source = Path(__file__).resolve().parent.parent / "probes" / "hypervisor.c"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    os.environ.pop("GITHUB_TOKEN", None)
    os.environ.pop("GH_TOKEN", None)
    directory = Path(os.environ["RUNNER_TEMP"]) / "debug" / "mtf-repeats"
    directory.mkdir(parents=True, exist_ok=True)
    mtf.emit({"event": "repeat_start", "kernel_uuid": uuid, "source_sha256": source_sha})
    details = {}
    with (directory / "rounds.jsonl").open("w", encoding="utf-8") as summary:
        def save(record):
            record.update({"event": "round_result", "source_sha256": source_sha,
                           "processes": details.get(record["round"], [])})
            summary.write(json.dumps(record, separators=(",", ":")) + "\n")
            summary.flush()
            os.fsync(summary.fileno())
            mtf.emit(record)

        def run(number, attempt):
            target = directory / ("round-" + str(number))
            target.mkdir(exist_ok=True)
            result = mtf.run_attempt(binary, target, "mtf-mov", attempt, "")
            pid = None
            try:
                path = target / ("mtf-mov-attempt" + str(attempt) + ".jsonl")
                records = [json.loads(line) for line in path.read_bytes().splitlines()]
                pids = {r.get("pid") for r in records if isinstance(r, dict)}
                if len(pids) == 1:
                    pid = next(iter(pids))
                if result in ("success", "retry") and (
                        not records or type(pid) is not int or pid <= 0
                        or any(not isinstance(r, dict) or r.get("sourcehash") != source_sha for r in records)
                        or hashlib.sha256(source.read_bytes()).hexdigest() != source_sha):
                    result = "identity_failure"
            except (OSError, ValueError, TypeError):
                if result in ("success", "retry"):
                    result = "identity_failure"
            details.setdefault(number, []).append({"attempt": attempt, "pid": pid, "result": result})
            return result

        ok = run_rounds(run, save)
    mtf.emit({"event": "repeat_complete", "result": "success" if ok else "failure"})
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
