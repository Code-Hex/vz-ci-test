#!/bin/bash
set -euo pipefail
debug_dir="${RUNNER_TEMP:?}/debug"
deadline=$(cat "$debug_dir/private/deadline")
session_name=$(cat "$debug_dir/private/session-name")
reason=deadline
while (( $(date +%s) < deadline )); do
  if [[ -e "$debug_dir/stop" ]]; then
    reason=stop_marker
    break
  fi
  status=$("$debug_dir/bin/upterm" session info "$session_name" -o json | jq -r '.status')
  printf '%s\t%s\n' "$(date -u +%FT%TZ)" "$status" | tee -a "$debug_dir/logs/heartbeat.tsv"
  if [[ "$status" == ended ]]; then
    reason=session_ended
    break
  fi
  sleep 10
done
printf '%s\thold_finished\t%s\n' "$(date -u +%FT%TZ)" "$reason" | tee -a "$debug_dir/logs/lifecycle.tsv"
