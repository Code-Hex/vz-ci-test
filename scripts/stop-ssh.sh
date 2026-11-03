#!/bin/bash
set -euo pipefail
debug_dir="${RUNNER_TEMP:?}/debug"
if [[ -x "$debug_dir/bin/upterm" && -f "$debug_dir/private/session-name" ]]; then
  session_name=$(cat "$debug_dir/private/session-name")
  exit_code=0
  "$debug_dir/bin/upterm" session stop "$session_name" \
    > "$debug_dir/logs/stop.log" 2>&1 || exit_code=$?
  printf '%s\tstop_finished\t%s\n' "$(date -u +%FT%TZ)" "$exit_code" >> "$debug_dir/logs/lifecycle.tsv"
  "$debug_dir/bin/upterm" session info "$session_name" -o json \
    | jq '{name,status,reason,exitCode,signal,tunnelReason}' \
    > "$debug_dir/logs/session-end.json" || true
  exit "$exit_code"
fi
