#!/usr/bin/env python3
"""Find bounded direct references to the Intel kernel panic timeout variable."""
import json
import os
from collections import deque
from pathlib import Path
import re
import subprocess
import sys
import tempfile

UUID = "87453B1D-A163-31FA-B33B-0FB4BE78E6E8"
KERNEL = "/System/Library/Kernels/kernel"
TARGET = "_panic_restart_timeout"
HANDLER = "_panic_set_restart_timeout"
LABEL = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+(.+?)\s*$")
RIP = re.compile(r"(?<![\w])(-?(?:0x[0-9a-fA-F]+|[0-9]+))\(%rip\)")
COMMENT = re.compile(r"#+\s*(?:0x)?([0-9a-fA-F]+)(?:\s|$|\s*<)")


def find_symbol(text, name):
    addresses = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] == name and re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            addresses.add(int(fields[0], 16))
    if len(addresses) != 1:
        raise ValueError("symbol_missing" if not addresses else "symbol_ambiguous")
    return addresses.pop()


def reference_access(text, symbol):
    match = re.search(r"\b(mov[a-z]*|lea[a-z]*)\s+(.+)", text)
    if not match:
        return "other"
    mnemonic, operands = match.group(1), match.group(2).split("#", 1)[0]
    if mnemonic.startswith("lea"):
        return "address"
    comma = operands.find(",")
    rip = operands.find("(%rip)")
    if comma < 0:
        return "other"
    if rip >= 0:
        return "read" if rip < comma else "write"
    if "<" + symbol + ">" in operands:
        before = operands.split("<" + symbol + ">", 1)[0]
        if "," not in before:
            return "read"
        lhs, rhs = before.split(",", 1)
        if not lhs.strip() and rhs.strip():
            return "read"
        if lhs.strip() and not rhs.strip():
            return "write"
    return "other"


def parse_disassembly(lines, target, symbol, known_handler):
    functions, references = {}, []
    history = deque(maxlen=3)
    function = "<unknown>"
    pending = None
    total, known, clipped = 0, False, False
    handler_access = set()
    name_ref = re.compile(r"<" + re.escape(symbol) + r">")

    def add_context(group, entries):
        nonlocal clipped
        for entry in entries:
            if entry not in group["context"]:
                if len(group["context"]) < 15:
                    group["context"].append(entry)
                else:
                    group["context_truncated"] = True
                    clipped = True

    def accept(entry, next_address):
        nonlocal total, known, clipped
        if entry is None:
            return
        address, text, owner = entry
        group = functions.get(owner)
        if group and group["tail"]:
            add_context(group, [text])
            group["tail"] -= 1
        evidence = None
        if name_ref.search(text):
            evidence = "symbol"
        else:
            comment = COMMENT.search(text)
            if comment and int(comment.group(1), 16) == target:
                evidence = "comment_address"
            else:
                rip = RIP.search(text)
                if rip and next_address is not None:
                    raw_offset = rip.group(1)
                    offset = int(raw_offset, 16 if "0x" in raw_offset.lower() else 10)
                    if (next_address + offset) & ((1 << 64) - 1) == target:
                        evidence = "rip_displacement"
        if evidence:
            total += 1
            access = reference_access(text, symbol)
            if owner == known_handler:
                known = True
                handler_access.add(access)
            if len(references) < 64 and (known_handler is None or owner == known_handler or len(references) < 62):
                references.append({"symbol_hint": owner, "address": "0x%x" % address, "evidence": evidence, "access": access})
                group = functions.setdefault(owner, {"symbol_hint": owner, "context": [], "context_truncated": False, "tail": 0})
                add_context(group, list(history) + [text])
                group["tail"] = 3
            else:
                clipped = True
        history.append(text)

    for line in lines:
        label = LABEL.match(line)
        if label:
            accept(pending, int(label.group(1), 16))
            pending = None
            function = label.group(2)
            history.clear()
            continue
        instruction = INSTRUCTION.match(line)
        if instruction:
            address = int(instruction.group(1), 16)
            accept(pending, address)
            pending = (address, line.strip()[:512], function)
    accept(pending, None)
    output = []
    for group in functions.values():
        group.pop("tail")
        output.append(group)
    return {"references": references, "symbol_hints": output, "total_matches": total,
            "truncated": clipped, "known_handler_xref": known, "handler_access": sorted(handler_access)}


def disassemble(binary, target, symbol, handler):
    process = subprocess.Popen(["xcrun", "llvm-objdump", "--disassemble", "--symbolize-operands",
                                "--no-show-raw-insn", str(binary)], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, errors="replace")
    try:
        result = parse_disassembly(process.stdout, target, symbol, handler)
        if process.wait() != 0:
            raise RuntimeError("objdump failed")
        return result
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()


def analyze_binary(binary, nm, target_symbol=TARGET, handler_symbol=HANDLER, on_metadata=None):
    result = {"status": "unsupported", "known_handler_xref": False,
              "scope": "symbol_hint is the nearest named label, not necessarily the actual function; direct static references only; indirect references, kernel collections, fixups and closed kexts are not excluded; address-taking does not prove a write"}
    try:
        target = find_symbol(nm, target_symbol)
    except ValueError as error:
        result["reason_enum"] = "target_missing" if str(error) == "symbol_missing" else "target_ambiguous"
        if on_metadata:
            on_metadata(result.copy())
        return result
    result["target_address"] = "0x%x" % target
    try:
        handler = find_symbol(nm, handler_symbol)
    except ValueError as error:
        handler = None
        result["reason_enum"] = "handler_missing" if str(error) == "symbol_missing" else "handler_ambiguous"
        result["handler_state"] = result["reason_enum"]
    else:
        result["handler_address"] = "0x%x" % handler
        result["handler_state"] = "found"
    if on_metadata:
        on_metadata(result.copy())
    try:
        scan = disassemble(binary, target, target_symbol, handler_symbol if handler is not None else None)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        result["reason_enum"] = "disassembly_failed"
        result["error_kind"] = type(error).__name__
        return result
    result.update(scan)
    access = set(scan["handler_access"])
    if handler is None:
        return result
    if scan["known_handler_xref"] and "read" in access and ("write" in access or "address" in access):
        result["status"] = "direct_refs_observed"
        result["reason_enum"] = "known_handler_verified"
    else:
        result["reason_enum"] = "known_handler_unverified"
    return result


def positive_control():
    with tempfile.TemporaryDirectory(prefix="kernel-ref-control-") as tmp:
        root = Path(tmp)
        source, binary = root / "control.c", root / "control"
        source.write_text("volatile unsigned long long needle=1; __attribute__((noinline)) unsigned long long control_handler(void){unsigned long long x=needle; needle=x+1; return x;} int main(void){return (int)control_handler();}")
        subprocess.run(["xcrun", "clang", "-target", "x86_64-apple-macos12", "-O1", str(source), "-o", str(binary)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        nm = subprocess.check_output(["xcrun", "nm", "-n", str(binary)], text=True, stderr=subprocess.DEVNULL, timeout=20)
        result = disassemble(binary, find_symbol(nm, "_needle"), "_needle", "_control_handler")
        return result["known_handler_xref"] and {"read", "write"}.issubset(result["handler_access"])


def validate_runner():
    if (os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("GITHUB_REPOSITORY") != "Code-Hex/vz-ci-test" or
            os.getenv("GITHUB_REF") != "refs/heads/main" or os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or
            not os.getenv("RUNNER_TEMP")):
        raise ValueError("runner guard rejected")
    system = subprocess.check_output(["/usr/bin/uname", "-s"], text=True, timeout=5).strip()
    machine = subprocess.check_output(["/usr/bin/uname", "-m"], text=True, timeout=5).strip()
    runtime_uuid = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.uuid"], text=True, timeout=5).strip().upper()
    dump = subprocess.check_output(["xcrun", "dwarfdump", "--uuid", KERNEL], text=True, timeout=20)
    matches = re.findall(r"UUID:\s*([0-9A-Fa-f-]+)\s*\(x86_64\)", dump)
    if system != "Darwin" or machine != "x86_64" or runtime_uuid != UUID or matches != [UUID]:
        raise ValueError("kernel UUID or architecture guard rejected")


def main():
    result = {"event": "kernel_timeout_refs", "status": "unsupported", "kernel_uuid": UUID}
    stage = "runner_guard_failed"
    try:
        validate_runner()
        stage = "positive_control_failed"
        result["positive_control"] = positive_control()
        if not result["positive_control"]:
            raise ValueError("synthetic Mach-O control failed")
        stage = "nm_failed"
        nm = subprocess.check_output(["xcrun", "nm", "-n", KERNEL], text=True, stderr=subprocess.DEVNULL, timeout=90)
        def publish_metadata(metadata):
            print(json.dumps({"event": "kernel_symbol_metadata", **metadata}, separators=(",", ":")), flush=True)

        result.update(analyze_binary(KERNEL, nm, on_metadata=publish_metadata))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["reason_enum"] = stage
        result["error_kind"] = type(error).__name__
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp and Path(runner_temp).is_dir():
        directory = Path(runner_temp) / "debug"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "kernel-timeout-refs.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, separators=(",", ":")), flush=True)
    return 0 if result["status"] == "direct_refs_observed" else 1


if __name__ == "__main__":
    sys.exit(main())
