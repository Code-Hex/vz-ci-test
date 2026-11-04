"""Strict local panic-report selection and recipient-only CMS encryption."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

KERNEL_UUID = "87453B1D-A163-31FA-B33B-0FB4BE78E6E8"
ROOTS = (Path("/Library/Logs/DiagnosticReports"), Path("/var/log/DiagnosticReports"),
         Path("/Users/runner/Library/Logs/DiagnosticReports"))
MAX_FILE = 4 * 1024 * 1024
MAX_FILES = 64
class NoReport(ValueError):
    pass


class UnstableReport(ValueError):
    pass


SIGNATURE = re.compile(r"^panic\(cpu [0-9]+(?: caller (?:0x)?[0-9a-fA-F]+)?\): dtrace: panic action at probe dtrace:::BEGIN \(ecb (?:0x)?[0-9a-fA-F]+\)(?:\s|$)")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise ValueError("report file invalid or oversized")
        data = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise UnstableReport("report changed during read")
    return data, {"device": before.st_dev, "inode": before.st_ino,
                  "size": before.st_size, "mtime_ns": before.st_mtime_ns, "sha256": digest(data)}


def inventory(roots=ROOTS):
    found = {}
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.iterdir():
            if not re.match(r"(?i)^(kernel|panic)", path.name) or path.suffix.lower() not in (".ips", ".panic"):
                continue
            if len(found) >= MAX_FILES:
                raise ValueError("too many candidate reports")
            data, info = read_regular(path)
            found[str(path)] = info
    return found


def match_report(data, suffix, trigger="panic-control", marker=None):
    text = data.decode("utf-8")
    if suffix.lower() == ".ips":
        decoder = json.JSONDecoder()
        position, objects = 0, []
        while position < len(text):
            while position < len(text) and text[position].isspace():
                position += 1
            if position >= len(text):
                break
            value, position = decoder.raw_decode(text, position)
            objects.append(value)
        if len(objects) not in (1, 2) or not all(isinstance(obj, dict) for obj in objects):
            raise ValueError("unexpected IPS format")
        uuids = [value for obj in objects if isinstance(obj, dict) for key, value in obj.items()
                 if key.replace("_", "").lower() == "kerneluuid"]
        if len(uuids) > 1 or any(not isinstance(value, str) or value.upper() != KERNEL_UUID for value in uuids):
            raise ValueError("kernel UUID mismatch")
        values = [obj["panicString"] for obj in objects if isinstance(obj, dict) and "panicString" in obj]
        if len(values) != 1 or not isinstance(values[0], str):
            raise ValueError("panicString absent or ambiguous")
        message = values[0]
        in_message = re.findall(r"(?im)^Kernel UUID:\s*([0-9a-f-]+)\s*$", message)
        if len(in_message) > 1 or any(value.upper() != KERNEL_UUID for value in in_message) or not (uuids or in_message):
            raise ValueError("kernel UUID missing or mismatch")
    elif suffix.lower() == ".panic":
        message = text.splitlines()[0] if text else ""
        if not message.startswith("panic("):
            raise ValueError("panic header invalid")
        uuids = re.findall(r"(?im)^Kernel UUID:\s*([0-9a-f-]+)\s*$", text)
        if len(uuids) != 1 or uuids[0].upper() != KERNEL_UUID:
            raise ValueError("kernel UUID missing or mismatch")
    else:
        raise ValueError("report suffix invalid")
    if trigger == "panic-control":
        matched = SIGNATURE.match(message)
    elif trigger == "panic-force-reset":
        if not isinstance(marker, str) or not re.fullmatch(r"vz-force-reset:[1-9][0-9]{0,19}:[1-9][0-9]{0,4}:[0-9a-f]{64}", marker):
            raise ValueError("force reset marker invalid")
        pattern = r"^panic\(cpu [0-9]+(?: caller (?:0x)?[0-9a-fA-F]+)?\): userspace panic: " + re.escape(marker) + r"(?=\r?\n|$)"
        matched = re.match(pattern, message)
    else:
        raise ValueError("unknown report trigger")
    if not matched:
        raise ValueError("panic signature mismatch")
    return True


def select_stable(roots, baseline, interval=2, trigger="panic-control", marker=None):
    previous = None
    selected = None
    for turn in range(3):
        current = inventory(roots)
        old_hashes = {info["sha256"] for info in baseline.values()}
        changed = [(path, info) for path, info in current.items() if info["sha256"] not in old_hashes]
        if not changed:
            raise NoReport("report candidate absent")
        if len(changed) != 1:
            raise ValueError("report candidates ambiguous")
        path, info = changed[0]
        data, reread = read_regular(Path(path))
        if reread != info:
            raise UnstableReport("report changed")
        identity = (path, info)
        if previous is not None and identity != previous:
            raise UnstableReport("report not stable")
        previous, selected = identity, {"data": data, "sha256": info["sha256"]}
        if turn < 2 and interval:
            time.sleep(interval)
    match_report(selected["data"], Path(previous[0]).suffix, trigger, marker)
    return selected


def cert_fingerprint(cert):
    if not cert or len(cert) > 32768:
        raise ValueError("invalid certificate")
    result = subprocess.run(["/usr/bin/openssl", "x509", "-inform", "PEM", "-outform", "DER"],
                            input=cert, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=10)
    return digest(result.stdout)


def encrypt_bundle(cert, metadata, report):
    fingerprint = cert_fingerprint(cert)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "recipient.pem"
        path.write_bytes(cert)
        public = subprocess.check_output(["/usr/bin/openssl", "x509", "-in", str(path), "-pubkey", "-noout"], stderr=subprocess.DEVNULL, timeout=10)
        key = Path(tmp) / "public.pem"
        key.write_bytes(public)
        detail = subprocess.check_output(["/usr/bin/openssl", "pkey", "-pubin", "-in", str(key), "-text", "-noout"], stderr=subprocess.DEVNULL, timeout=10)
        if not re.search(rb"(?:RSA )?Public-Key:\s*\(4096 bit\)", detail):
            raise ValueError("certificate key must be RSA-4096")
        bundle = json.dumps({"metadata": metadata, "report_sha256": digest(report),
                             "report_base64": base64.b64encode(report).decode()}, separators=(",", ":")).encode()
        compressed = gzip.compress(bundle, mtime=0)
        encrypted = subprocess.run(["/usr/bin/openssl", "cms", "-encrypt", "-aes256", "-binary", "-outform", "DER",
                                    "-recip", str(path), "-keyopt", "rsa_padding_mode:oaep",
                                    "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"],
                                   input=compressed, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=20).stdout
    encoded = base64.b64encode(encrypted).decode()
    if len(encoded.encode()) > 58000:
        raise ValueError("encrypted bundle oversized")
    return {"cert_fingerprint": fingerprint, "cipher_sha256": digest(encrypted), "ciphertext": encoded}
