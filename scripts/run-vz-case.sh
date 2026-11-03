#!/bin/bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo 'usage: run-vz-case.sh TestRun|TestStop|TestRuntimeNetworkConnection 1|2|3' >&2
  exit 64
fi
target=$1
count=$2
case "$target" in
  TestRun|TestStop|TestRuntimeNetworkConnection) ;;
  *) echo 'Unsupported diagnostic test target' >&2; exit 64 ;;
esac
case "$count" in
  1|2|3) ;;
  *) echo 'Count must be 1, 2, or 3' >&2; exit 64 ;;
esac
[[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
  echo 'Run VZ cases on the Intel macOS runner' >&2
  exit 1
}

debug_dir="${RUNNER_TEMP:?}/debug"
source_dir="$debug_dir/vz"
binary="$source_dir/vz.test"
[[ -x "$binary" && -f "$debug_dir/vz-go-version.txt" ]] || {
  echo 'Run prepare-vz.sh first' >&2
  exit 1
}
export VZ_DIAGNOSTIC_GO="$(cat "$debug_dir/vz-go-version.txt")"
[[ "$VZ_DIAGNOSTIC_GO" == go1.26.8 ]]
export VZ_DIAGNOSTIC_CASE="$target-count$count"
export VZ_DIAGNOSTIC_TARGET="$target"
export VZ_DIAGNOSTIC_COUNT="$count"
export VZ_DIAGNOSTIC_PROCESS_NUMBER=1
cd "$source_dir"
codesign --verify --strict --verbose=2 "$binary"
shasum -a 256 "$binary"
printf 'VZ_DIAGNOSTIC case=%s target=%s count=%s go=%s processNumber=%s\n' \
  "$VZ_DIAGNOSTIC_CASE" "$target" "$count" "$VZ_DIAGNOSTIC_GO" \
  "$VZ_DIAGNOSTIC_PROCESS_NUMBER"
exec "$binary" "-test.run=^$target$" "-test.count=$count" -test.timeout=2m -test.v
