#!/bin/bash
set -euo pipefail
python3 - <<'PY'
import base64
import os
import re
import struct
import sys

key = os.environ.get("SSH_PUBLIC_KEY", "")
duration = os.environ.get("DURATION_MINUTES", "")
if not re.fullmatch(r"[1-9][0-9]?", duration) or int(duration) > 60:
    sys.exit("duration_minutes must be an integer from 1 through 60")
if "\n" in key or "\r" in key:
    sys.exit("ssh_public_key must contain exactly one line")
parts = key.split()
if len(parts) < 2 or parts[0] != "ssh-ed25519":
    sys.exit("ssh_public_key must be a single Ed25519 public key without key options")
try:
    decoded = base64.b64decode(parts[1], validate=True)
except ValueError:
    sys.exit("ssh_public_key has invalid base64")
prefix = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
if len(decoded) != len(prefix) + 32 or not decoded.startswith(prefix):
    sys.exit("ssh_public_key has an invalid Ed25519 key encoding")
print("Validated one Ed25519 key and a bounded session duration")
PY
