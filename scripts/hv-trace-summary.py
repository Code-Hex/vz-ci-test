#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, dataclass
from datetime import datetime
import json
import re
import sys
import threading
import time


FAMILIES = {
    0x01AC0000: "enter",
    0x01AC0008: "task_trap",
    0x01AC000C: "thread_trap",
    0x01AC0094: "run_until",
}
TRACE_LOST_EVENTS = 0x07020008
MAX_OUTPUT_BYTES = 8192
COUNTERS = (
    "lines", "events", "tracked", "balanced", "orphan", "overwritten",
    "untracked", "unflagged", "malformed", "ignored", "traceLostIndicators",
    "pendingDropped", "rawTruncated", "familyEventCountsDropped",
    "unknownActor",
)
EVENT = re.compile(
    r"^\s*(\d{1,20})\s+\S+\s+([0-9a-fA-F]{7,8})\s+"
    r"([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})\s+"
    r"([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})\s+"
    r"([0-9a-fA-F]{1,16})\s+(\d+)(?:\([^)]*\))?\s+(.+)\((\d{1,10})\)\s*$"
)
LOSS_TEXT = re.compile(r"\b(?:lost|dropped|overrun|overflow|wrapped)\b", re.I)
TEXT_CLOCK = "ktrace_text_abstime"
NDJSON_CLOCK = "ktrace_relative_ns"
DECIMAL = re.compile(r"[0-9]{1,20}\Z")
WALLTIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?UTC\Z")


def error_sample(kind: str, line: str) -> dict:
    truncated = len(line) > 512
    raw = line[:256] + "..." + line[-253:] if truncated else line
    return {"kind": kind, "raw": raw, "rawLength": len(line), "rawTruncated": truncated}


@dataclass(frozen=True)
class TraceRecord:
    timestamp: int
    code: int
    pid: int | None
    tid: int
    process: str | None
    raw: str
    args: tuple[int, int, int, int]
    cpu: int
    clock: str
    walltime: str | None


@dataclass(frozen=True)
class Pending:
    pid: int
    tid: str
    family: str
    timestamp: int
    process: str | None
    raw: str
    rawTruncated: bool
    clock: str
    walltime: str | None


def unsigned(value, bits: int, decimal_string: bool = False) -> int:
    if decimal_string:
        if type(value) is not str or DECIMAL.fullmatch(value) is None:
            raise ValueError("expected an unsigned decimal string")
        value = int(value)
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError("unsigned value outside its numeric range")
    return value


def parse_ndjson(line: str) -> TraceRecord:
    row = json.loads(line)
    if type(row) is not dict:
        raise ValueError("expected a ktrace NDJSON object")
    timestamp = unsigned(row.get("timestampns"), 64, decimal_string=True)
    code = unsigned(row.get("debugid"), 32)
    tid = unsigned(row.get("threadid"), 64, decimal_string=True)
    cpu = unsigned(row.get("cpuid"), 32)
    args = row.get("args")
    if type(args) is not list or len(args) != 4:
        raise ValueError("expected four NDJSON arguments")
    args = tuple(unsigned(value, 64, decimal_string=True) for value in args)
    pid = row.get("pid")
    if pid is None or (type(pid) is int and pid < 0):
        pid = None
    else:
        pid = unsigned(pid, 32)
    process = row.get("execname")
    if process is not None and type(process) is not str:
        raise ValueError("expected an execname string or null")
    walltime = row.get("walltime")
    if type(walltime) is not str or WALLTIME.fullmatch(walltime) is None:
        raise ValueError("expected a UTC walltime")
    datetime.fromisoformat(walltime[:-3])
    return TraceRecord(timestamp, code, pid, tid, process, line, args, cpu, NDJSON_CLOCK, walltime)


def parse_event(line: str) -> TraceRecord | None:
    if not line.strip() or ("abstime" in line and "debug-id" in line):
        return None
    if line.lstrip().startswith(("{", "[")):
        return parse_ndjson(line)
    match = EVENT.match(line)
    if match is None:
        raise ValueError("malformed trace row")
    timestamp, code, a0, a1, a2, a3, tid, cpu, process, pid = match.groups()
    timestamp, pid = int(timestamp), int(pid)
    if timestamp >= 1 << 64 or pid >= 1 << 32:
        raise ValueError("trace timestamp or PID exceeds its numeric range")
    args = tuple(int(value, 16) for value in (a0, a1, a2, a3))
    return TraceRecord(timestamp, int(code, 16), pid, int(tid, 16), process, line,
                       args, unsigned(int(cpu), 32), TEXT_CLOCK, None)


class Tracker:
    def __init__(self, max_pending: int = 128):
        if not 1 <= max_pending <= 4096:
            raise ValueError("max_pending must be between 1 and 4096")
        self.max_pending = max_pending
        self.lock = threading.Lock()
        self.counts = Counter({name: 0 for name in COUNTERS})
        self.families = {
            name: Counter({key: 0 for key in ("starts", "ends", "balanced", "orphan", "overwritten")})
            for name in FAMILIES.values()
        }
        self.pending: OrderedDict[tuple[str, int, int, int], Pending] = OrderedDict()
        self.observed_families: Counter[str] = Counter()
        self.recent_errors: deque[dict] = deque(maxlen=2)
        self.recent_unattributed: deque[dict] = deque(maxlen=2)
        self.last_timestamp: int | None = None
        self.last_clock: str | None = None
        self.clock_counts = Counter({TEXT_CLOCK: 0, NDJSON_CLOCK: 0})

    def feed(self, line: str) -> None:
        line = line.rstrip("\r\n")
        try:
            record = parse_event(line)
            failure = None
        except ValueError:
            record = None
            failure = "traceLostIndicators" if LOSS_TEXT.search(line) else "malformed"
        with self.lock:
            self.counts["lines"] += 1
            if failure is not None:
                self.counts[failure] += 1
                self.recent_errors.append(error_sample(failure, line))
                return
            if record is None:
                self.counts["ignored"] += 1
                return
            self.counts["events"] += 1
            self.last_timestamp = record.timestamp
            self.last_clock = record.clock
            self.clock_counts[record.clock] += 1
            base = record.code & ~3
            if record.pid is None:
                self.counts["unknownActor"] += 1
                self.recent_unattributed.append(error_sample("unknownActor", line))
            if base == TRACE_LOST_EVENTS:
                self.counts["traceLostIndicators"] += 1
                self.recent_errors.append(error_sample("traceLostIndicators", line))
                return
            if record.code >> 16 != 0x01AC:
                self.counts["ignored"] += 1
                return
            family_code = hex(base)
            if family_code in self.observed_families or len(self.observed_families) < 16:
                self.observed_families[family_code] += 1
            else:
                self.counts["familyEventCountsDropped"] += 1
            if base not in FAMILIES or record.pid is None:
                self.counts["untracked"] += 1
                return
            self.counts["tracked"] += 1
            family = self.families[FAMILIES[base]]
            key = (record.clock, record.pid, record.tid, base)
            edge = record.code & 3
            if edge == 1:
                family["starts"] += 1
                if key in self.pending:
                    self.pending.pop(key)
                    family["overwritten"] += 1
                    self.counts["overwritten"] += 1
                elif len(self.pending) == self.max_pending:
                    self.pending.popitem(last=False)
                    self.counts["pendingDropped"] += 1
                truncated = len(record.raw) > 512 or (record.process is not None and len(record.process) > 80)
                self.counts["rawTruncated"] += int(truncated)
                self.pending[key] = Pending(
                    record.pid, f"{record.tid:x}", FAMILIES[base], record.timestamp,
                    record.process[:80] if record.process is not None else None,
                    record.raw[:512], truncated, record.clock, record.walltime,
                )
            elif edge == 2:
                family["ends"] += 1
                if self.pending.pop(key, None) is None:
                    family["orphan"] += 1
                    self.counts["orphan"] += 1
                else:
                    family["balanced"] += 1
                    self.counts["balanced"] += 1
            else:
                self.counts["unflagged"] += 1

    def snapshot(self, final: bool = False) -> dict:
        with self.lock:
            pending = [asdict(item) for item in reversed(self.pending.values())][:16]
            return {
                "type": "hv_trace_summary", "scope": "received_trace_prefix", "final": final,
                "counts": dict(self.counts),
                "families": {name: dict(counts) for name, counts in self.families.items()},
                "observedFamilies": dict(self.observed_families),
                "lastTimestamp": self.last_timestamp,
                "lastClock": self.last_clock, "clockCounts": dict(self.clock_counts),
                "pendingCount": len(self.pending), "pending": pending,
                "pendingOmitted": len(self.pending) - len(pending),
                "recentErrors": list(self.recent_errors),
                "recentUnattributed": list(self.recent_unattributed),
            }


def encode_snapshot(snapshot: dict) -> str:
    packet = dict(snapshot)
    packet["pending"] = list(snapshot["pending"])
    packet["recentErrors"] = list(snapshot["recentErrors"])
    packet["recentUnattributed"] = list(snapshot["recentUnattributed"])
    while True:
        packet["pendingOmitted"] = packet["pendingCount"] - len(packet["pending"])
        encoded = json.dumps(packet, separators=(",", ":"), ensure_ascii=True) + "\n"
        if len(encoded) <= MAX_OUTPUT_BYTES:
            return encoded
        if packet["pending"]:
            packet["pending"].pop()
        elif packet["recentErrors"]:
            packet["recentErrors"].pop(0)
        elif packet["recentUnattributed"]:
            packet["recentUnattributed"].pop(0)
        else:
            raise ValueError("snapshot metadata exceeds the output limit")


def main() -> None:
    argparse.ArgumentParser(description="Summarize received ktrace NDJSON or -t -N rows once per second; pending is not a CPU-state verdict.").parse_args()
    tracker = Tracker()
    stop = threading.Event()
    output_closed = threading.Event()
    started = time.monotonic()
    sequence = 0
    stop_reason = "eof"

    def emit(final: bool) -> None:
        nonlocal sequence
        snapshot = tracker.snapshot(final=final)
        snapshot["sequence"] = sequence
        snapshot["collectorElapsed"] = round(time.monotonic() - started, 3)
        if final:
            snapshot["stopReason"] = stop_reason
        sequence += 1
        try:
            sys.stdout.write(encode_snapshot(snapshot))
            sys.stdout.flush()
        except BrokenPipeError:
            output_closed.set()
            stop.set()

    def periodic() -> None:
        while not stop.wait(1):
            emit(False)

    writer = threading.Thread(target=periodic, daemon=True)
    writer.start()
    try:
        for line in sys.stdin:
            tracker.feed(line)
            if output_closed.is_set():
                break
    except KeyboardInterrupt:
        stop_reason = "interrupt"
    finally:
        stop.set()
        writer.join()
        if not output_closed.is_set():
            emit(True)


if __name__ == "__main__":
    main()
