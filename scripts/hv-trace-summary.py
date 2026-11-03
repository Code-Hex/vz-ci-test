#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, dataclass
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
)
EVENT = re.compile(
    r"^\s*(\d{1,20})\s+\S+\s+([0-9a-fA-F]{7,8})\s+"
    r"([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})\s+"
    r"([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})\s+"
    r"([0-9a-fA-F]{1,16})\s+\d+(?:\([^)]*\))?\s+(.+)\((\d{1,10})\)\s*$"
)
LOSS_TEXT = re.compile(r"\b(?:lost|dropped|overrun|overflow|wrapped)\b", re.I)


@dataclass(frozen=True)
class TraceRecord:
    timestamp: int
    code: int
    pid: int
    tid: int
    process: str
    raw: str


@dataclass(frozen=True)
class Pending:
    pid: int
    tid: str
    family: str
    timestamp: int
    process: str
    raw: str
    rawTruncated: bool


def parse_event(line: str) -> TraceRecord | None:
    if not line.strip() or ("abstime" in line and "debug-id" in line):
        return None
    match = EVENT.match(line)
    if match is None:
        raise ValueError("malformed trace row")
    timestamp, code, _, _, _, _, tid, process, pid = match.groups()
    timestamp, pid = int(timestamp), int(pid)
    if timestamp >= 1 << 64 or pid >= 1 << 32:
        raise ValueError("trace timestamp or PID exceeds its numeric range")
    return TraceRecord(timestamp, int(code, 16), pid, int(tid, 16), process, line)


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
        self.pending: OrderedDict[tuple[int, int, int], Pending] = OrderedDict()
        self.observed_families: Counter[str] = Counter()
        self.recent_errors: deque[dict[str, str]] = deque(maxlen=2)
        self.last_timestamp: int | None = None

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
                self.recent_errors.append({"kind": failure, "raw": line[:160]})
                return
            if record is None:
                self.counts["ignored"] += 1
                return
            self.counts["events"] += 1
            self.last_timestamp = record.timestamp
            base = record.code & ~3
            if base == TRACE_LOST_EVENTS:
                self.counts["traceLostIndicators"] += 1
                self.recent_errors.append({"kind": "traceLostIndicators", "raw": line[:160]})
                return
            if record.code >> 16 != 0x01AC:
                self.counts["ignored"] += 1
                return
            family_code = hex(base)
            if family_code in self.observed_families or len(self.observed_families) < 16:
                self.observed_families[family_code] += 1
            else:
                self.counts["familyEventCountsDropped"] += 1
            if base not in FAMILIES:
                self.counts["untracked"] += 1
                return
            self.counts["tracked"] += 1
            family = self.families[FAMILIES[base]]
            key = (record.pid, record.tid, base)
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
                truncated = len(record.raw) > 512 or len(record.process) > 80
                self.counts["rawTruncated"] += int(truncated)
                self.pending[key] = Pending(
                    record.pid, f"{record.tid:x}", FAMILIES[base], record.timestamp,
                    record.process[:80], record.raw[:512], truncated,
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
                "pendingCount": len(self.pending), "pending": pending,
                "pendingOmitted": len(self.pending) - len(pending),
                "recentErrors": list(self.recent_errors),
            }


def encode_snapshot(snapshot: dict) -> str:
    packet = dict(snapshot)
    packet["pending"] = list(snapshot["pending"])
    packet["recentErrors"] = list(snapshot["recentErrors"])
    while True:
        packet["pendingOmitted"] = packet["pendingCount"] - len(packet["pending"])
        encoded = json.dumps(packet, separators=(",", ":"), ensure_ascii=True) + "\n"
        if len(encoded) <= MAX_OUTPUT_BYTES:
            return encoded
        if packet["pending"]:
            packet["pending"].pop()
        elif packet["recentErrors"]:
            packet["recentErrors"].pop(0)
        else:
            raise ValueError("snapshot metadata exceeds the output limit")


def main() -> None:
    argparse.ArgumentParser(description="Summarize received ktrace -t -N rows once per second; pending is not a CPU-state verdict.").parse_args()
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
