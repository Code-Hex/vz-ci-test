#!/bin/bash
set -euo pipefail
[[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
  echo 'This diagnostic session requires an Intel macOS runner' >&2
  exit 1
}
umask 077
debug_dir="${RUNNER_TEMP:?}/debug"
mkdir -p "$debug_dir/bin" "$debug_dir/private" "$debug_dir/public" "$debug_dir/logs"
archive="$debug_dir/private/upterm.tar.gz"
curl --fail --silent --show-error --location --retry 3 \
  --connect-timeout 15 --max-time 120 \
  https://github.com/owenthereal/upterm/releases/download/v0.41.0/upterm_darwin_amd64.tar.gz \
  -o "$archive"
expected=fc77ec6fe37955dc7208d2eb14c74c6001ad7e9ccc5c15d11f0ecbfb4319f53c
actual=$(shasum -a 256 "$archive" | awk '{print $1}')
[[ "$actual" == "$expected" ]] || { echo 'Upterm checksum mismatch' >&2; exit 1; }
tar -xzf "$archive" -C "$debug_dir/bin" upterm
chmod 700 "$debug_dir/bin/upterm"
"$debug_dir/bin/upterm" version
printf '%s\tinstalled\tupterm-v0.41.0\n' "$(date -u +%FT%TZ)" >> "$debug_dir/logs/lifecycle.tsv"
