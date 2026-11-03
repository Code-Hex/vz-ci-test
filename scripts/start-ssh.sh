#!/bin/bash
set -euo pipefail
bash "$(dirname "$0")/validate-ssh-inputs.sh"
umask 077
debug_dir="${RUNNER_TEMP:?}/debug"
upterm="$debug_dir/bin/upterm"
session_name="intel-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
printf '%s\n' "$session_name" > "$debug_dir/private/session-name"
printf '%s\n' "$SSH_PUBLIC_KEY" > "$debug_dir/private/authorized_keys"
ssh-keygen -lf "$debug_dir/private/authorized_keys" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C 'ephemeral-runner-relay' -f "$debug_dir/private/relay_identity"
cat > "$debug_dir/public/relay-known-hosts" <<'EOF'
@cert-authority uptermd.upterm.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4
EOF
date +%s | awk -v minutes="$DURATION_MINUTES" '{print $1 + minutes * 60}' > "$debug_dir/private/deadline"
printf '%s\tstarting\t%s\n' "$(date -u +%FT%TZ)" "$session_name" >> "$debug_dir/logs/lifecycle.tsv"
exit_code=0
"$upterm" host --detach --accept --name "$session_name" \
  --private-key "$debug_dir/private/relay_identity" \
  --authorized-keys "$debug_dir/private/authorized_keys" \
  --known-hosts "$debug_dir/public/relay-known-hosts" \
  --server ssh://uptermd.upterm.dev:22 \
  --allow-exec --no-forwarding --join-timeout 5m \
  -o json -- /bin/bash \
  > "$debug_dir/private/session.json" 2> "$debug_dir/logs/start.log" || exit_code=$?
printf '%s\tstart_finished\t%s\n' "$(date -u +%FT%TZ)" "$exit_code" >> "$debug_dir/logs/lifecycle.tsv"
if (( exit_code != 0 )); then
  cat "$debug_dir/logs/start.log" >&2
  exit "$exit_code"
fi
jq -e '.access == "allowlist" and .status == "ready"' "$debug_dir/private/session.json" >/dev/null
jq '{name, sessionId, host, sshCommand, sshConfig, status, access}' \
  "$debug_dir/private/session.json" > "$debug_dir/public/connection.json"
python3 - <<'PY' > "$debug_dir/public/runner-info.json"
import datetime
import json
import os
import platform
import subprocess

print(json.dumps({
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "uname": platform.uname()._asdict(),
    "sw_vers": subprocess.check_output(["sw_vers"], text=True),
    "uid": os.getuid(),
    "gid": os.getgid(),
    "run_id": os.environ["GITHUB_RUN_ID"],
    "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    "workflow_sha": os.environ["GITHUB_SHA"],
    "runner_arch": os.environ.get("RUNNER_ARCH"),
    "runner_temp": os.environ["RUNNER_TEMP"],
    "workspace": os.environ["GITHUB_WORKSPACE"],
}, indent=2))
PY
printf '%s\tready\t%s\n' "$(date -u +%FT%TZ)" "$session_name" >> "$debug_dir/logs/lifecycle.tsv"
echo "SSH session ready: $session_name"
