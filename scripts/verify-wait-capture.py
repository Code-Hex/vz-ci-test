#!/usr/bin/env python3
"""Autonomous timer control with bounded PC and waiter observation."""
import importlib.util
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(os.environ["RUNNER_TEMP"]) / "debug" / "wait-capture"
PROBES = Path(os.environ["RUNNER_TEMP"]) / "debug" / "probes"
UUID = "87453B1D-A163-31FA-B33B-0FB4BE78E6E8"
spec = importlib.util.spec_from_file_location("controls", ROOT / "scripts/verify-cr8-controls.py")
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
OUT.mkdir(parents=True, exist_ok=True)
report_queue = queue.Queue(maxsize=256)
dropped = 0
children = []
traces = []


def report(value):
    global dropped
    try:
        report_queue.put_nowait(value)
    except queue.Full:
        dropped += 1


def printer():
    while True:
        item = report_queue.get()
        try:
            if item is None:
                return
            print(json.dumps(item, separators=(",", ":")), flush=True)
        finally:
            report_queue.task_done()


threading.Thread(target=printer, daemon=True).start()


class Reader:
    def __init__(self, proc, filename, callback=None):
        self.proc, self.records, self.root_pid = proc, [], None
        self.callback = callback
        self.thread = threading.Thread(target=self.read, args=(filename,), daemon=True)
        self.thread.start()

    def read(self, filename):
        with (OUT / filename).open("w", buffering=1) as raw:
            for line in self.proc.stdout:
                raw.write(line)
                if line.startswith("DTRACE_PID="):
                    try:
                        self.root_pid = int(line.split("=", 1)[1])
                    except ValueError:
                        pass
                    continue
                try:
                    value = json.loads(line)
                except ValueError:
                    value = {"raw": line.rstrip()}
                if isinstance(value, dict):
                    if value.get("event") != "pc_snapshot" and len(self.records) < 10000:
                        self.records.append(value)
                    if self.callback:
                        self.callback(value)


def start(command, filename, callback=None, stdin=False):
    proc = subprocess.Popen(command, stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, start_new_session=True)
    children.append(proc)
    return Reader(proc, filename, callback)


def until(predicate, seconds, label):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise RuntimeError(label)


def owned_dtrace(args, filename):
    reader = start(["sudo", "-n", "sh", "-c", 'echo "DTRACE_PID=$$"; exec "$@"',
                    "sh", "/usr/sbin/dtrace", *args], filename)
    traces.append(reader)
    return reader


def stop_dtrace(reader):
    if reader.proc.poll() is not None:
        return
    if not reader.root_pid:
        report({"event": "dtrace_cleanup_incomplete", "reason": "owned_pid_missing"})
        return
    if reader.root_pid:
        try:
            subprocess.run(["sudo", "-n", "kill", "-INT", str(reader.root_pid)],
                           timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            reader.proc.wait(timeout=4)
        except (subprocess.TimeoutExpired, OSError):
            report({"event": "dtrace_cleanup_incomplete", "pid": reader.root_pid})


def kill_owned(proc):
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=2)
        except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired) as error:
            report({"event": "child_cleanup_incomplete", "pid": proc.pid, "error": str(error)})


def run_register_control():
    source = (ROOT / "probes/wait-register-control.d").read_text()
    source = source.replace("bufpolicy=fill", "bufpolicy=switch")
    source += '\ndtrace:::BEGIN { printf("{\\"type\\":\\"armed\\"}\\n"); }\n'
    control_d = OUT / "register-control-runtime.d"
    control_d.write_text(source)
    control = start([str(PROBES / "wait-register-control"), "30000000"], "register-control.jsonl", stdin=True)
    until(lambda: control.records or control.proc.poll() is not None, 5, "register header missing")
    if not control.records or control.records[0].get("type") != "ready":
        raise RuntimeError("invalid register header")
    header = control.records[0]
    trace = owned_dtrace(["-C", "-s", str(control_d), str(header["pid"]),
                          str(header["loop_begin"]), str(header["loop_end"])], "register-trace.jsonl")
    until(lambda: trace.root_pid and any(x.get("type") == "armed" for x in trace.records), 10, "register trace not armed")
    control.proc.stdin.write("G")
    control.proc.stdin.flush()
    control.proc.wait(timeout=30)
    trace.proc.wait(timeout=15)
    trace.thread.join(2)
    summaries = [x for x in trace.records if x.get("type") == "summary"]
    if (control.proc.returncode != 0 or trace.proc.returncode != 0 or len(summaries) != 1 or
            summaries[0].get("valid", 0) < 20 or summaries[0].get("mismatch") != 0 or
            summaries[0].get("error_seen") != 0 or summaries[0].get("out_of_range_cpu") != 0):
        raise RuntimeError("register positive control failed")
    report({"event": "register_control_pass", "summary": summaries[0]})


last_snapshot = None
last_wait = [0] * 4
wait_positive = False
last_report = 0
last_received = 0
fresh_first = None
fresh_advanced = False


def observe(value):
    global last_snapshot, last_report, last_received, wait_positive, fresh_first, fresh_advanced
    if value.get("event") != "pc_snapshot":
        return
    last_snapshot = value
    last_received = time.monotonic()
    if ready_snapshot():
        generations = [x["seq_before"] for x in value["cpus"]]
        if fresh_first is None:
            fresh_first = generations
        elif all(now > before for now, before in zip(generations, fresh_first)):
            fresh_advanced = True
    valid = (value.get("armed") and value.get("mach_write_bracket_valid") and
             value.get("out_of_range_cpu") == 0 and not value.get("wait_observer_error_seen"))
    for item in value.get("waits", []):
        cpu = item.get("cpu")
        if cpu not in range(4):
            continue
        if valid and item.get("captured") and item.get("trustworthy") and item.get("invalid_count") == 0 and item.get("error_seen") == 0:
            wait_positive = True
            seq = item.get("seq_before", 0)
            if seq > last_wait[cpu]:
                last_wait[cpu] = seq
                report({"event": "latched_wait", "snapshot": value.get("snapshot"), "record": item,
                        "export_timestamp_ns": value.get("export_timestamp_ns"), "dropped": dropped})
    if time.monotonic() - last_report >= 1:
        last_report = time.monotonic()
        report({"event": "cpu_summary", "snapshot": value.get("snapshot"),
                "armed": value.get("armed"), "mach_before_write_ns": value.get("mach_before_write_ns"),
                "mach_after_write_ns": value.get("mach_after_write_ns"),
                "export_timestamp_ns": value.get("export_timestamp_ns"),
                "error": value.get("wait_observer_error_seen"), "cpus": value.get("cpus"),
                "wait_health": [{key: item.get(key) for key in (
                    "cpu", "seq_before", "seq_after", "coherent", "trustworthy",
                    "counter_transport_valid", "invalid_count", "error_seen", "captured",
                    "age_at_export_ns", "current_profile_generation", "latest_profile_is_wait_sample")}
                    for item in value.get("waits", [])], "dropped": dropped})


def ready_snapshot():
    s = last_snapshot
    if not s or time.monotonic() - last_received > 1 or not s.get("armed") or not s.get("mach_write_bracket_valid") or s.get("out_of_range_cpu") != 0 or s.get("wait_observer_error_seen"):
        return False
    cpus = s.get("cpus", [])
    waits = s.get("waits", [])
    def sequence_valid(item, minimum):
        before = item.get("seq_before")
        return (isinstance(before, int) and before >= minimum and before % 2 == 0 and
                before == item.get("seq_after") and not item.get("sequence_regressed"))
    return (len(cpus) == 4 and len(waits) == 4 and
            all(x.get("cpu") == i and x.get("coherent") and sequence_valid(x, 4) and
                x.get("age_at_export_ns", 10**12) < 250000000 for i, x in enumerate(cpus)) and
            all(x.get("cpu") == i and x.get("coherent") and x.get("trustworthy") and
                x.get("counter_transport_valid") and x.get("invalid_count") == 0 and
                x.get("error_seen") == 0 and sequence_valid(x, 2) for i, x in enumerate(waits)))


def timer_fact(phase, value):
    if value.get("api") in {"probe_start", "owner_thread_id", "hv_vcpu_run_until", "guest_observation",
                            "timer_guest_state", "sentinel_spin_verified", "sentinel_hlt_timer_verified",
                            "guest_not_established", "phase_result", "process_result"}:
        report({"event": "timer_fact", "phase": phase, "fact": value, "dropped": dropped})


def run_timer(phase, timeout):
    proc = start([str(PROBES / "hypervisor"), controls.PHASES[phase][0]], phase + ".jsonl",
                 lambda x: timer_fact(phase, x))
    start_time = time.monotonic()
    while proc.proc.poll() is None and time.monotonic() - start_time < timeout:
        report({"event": "timer_heartbeat", "phase": phase, "elapsed": round(time.monotonic() - start_time, 2), "dropped": dropped})
        time.sleep(2)
    timed_out = proc.proc.poll() is None
    if timed_out:
        kill_owned(proc.proc)
    proc.thread.join(2)
    result = controls.classify(phase, proc.records, proc.proc.poll(), timed_out)
    report({"event": "timer_result", "phase": phase, "result": result, "exit": proc.proc.poll(), "dropped": dropped})
    return result


def main():
    trace = None
    result = "failure"
    try:
        uuid = subprocess.check_output(["sysctl", "-n", "kern.uuid"], text=True).strip()
        if uuid != UUID:
            raise RuntimeError("kernel UUID mismatch")
        run_register_control()
        helper = start([str(PROBES / "pc-sampler"), "120000", "10"], "snapshots.jsonl", observe)
        until(lambda: helper.records and helper.records[0].get("event") == "pc_sampler_buffer", 5, "sampler header missing")
        header = helper.records[0]
        if header.get("bytes") != 4096 or header.get("cpu_slots") != 4:
            raise RuntimeError("sampler header invalid")
        trace = owned_dtrace(["-C", "-I", str(ROOT / "probes"), "-w", "-s", str(ROOT / "probes/pc_sampler.d"),
                              str(header["pid"]), str(header["address"]), str(header["fd"])], "sampler-dtrace.jsonl")
        until(lambda: trace.root_pid and trace.proc.poll() is None and helper.proc.poll() is None and ready_snapshot() and fresh_advanced and wait_positive, 30, "fresh four-CPU / natural wait control missing")
        report({"event": "sampler_control_pass", "dropped": dropped})
        if run_timer("timer-spin", 20) != "success":
            raise RuntimeError("spin control failed")
        if not ready_snapshot() or helper.proc.poll() is not None or trace.proc.poll() is not None:
            raise RuntimeError("sampler no longer ready after spin")
        result = run_timer("timer-hlt", 45)
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyError, ValueError) as error:
        report({"event": "controller_error", "error": str(error), "dropped": dropped})
    finally:
        for owned_trace in traces:
            stop_dtrace(owned_trace)
        for proc in children:
            kill_owned(proc)
        deadline = time.monotonic() + 2
        while report_queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        summary = {"event": "wait_capture_summary", "result": result, "dropped": dropped,
                   "unflushed_before_summary": report_queue.unfinished_tasks}
        (OUT / "summary.json").write_text(json.dumps(summary) + "\n")
        report(summary)
        deadline = time.monotonic() + 1
        while report_queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        summary["unflushed_after_flush"] = report_queue.unfinished_tasks
        summary["dropped_after_flush"] = dropped
        (OUT / "summary.json").write_text(json.dumps(summary) + "\n")
    return 0 if result == "success" else 1


if __name__ == "__main__":
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    sys.exit(main())
