#!/bin/bash
set -euo pipefail

[[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
  echo 'Run this preparation on the Intel macOS runner' >&2
  exit 1
}

cd "$(dirname "$0")/.."
diagnostic_root=$PWD
debug_dir="${RUNNER_TEMP:?}/debug"
source_dir="$debug_dir/vz"
idle_patch="$diagnostic_root/probes/vz-idle.patch"
phase_patch="$diagnostic_root/probes/vz-phases.patch"
binary="$source_dir/vz.test"
source_sha=90ea0b8338dc8b482e315084f31e6ef6b194805f
phase=source
expected_index=""
finish() {
  result=$?
  if [[ -n "$expected_index" ]]; then
    rm -f "$expected_index" "$expected_index.lock"
  fi
  printf 'VZ_DIAGNOSTIC idle.prepare phase=%s exitCode=%d\n' "$phase" "$result"
}
trap finish EXIT
unset VZ_DIAGNOSTIC_IDLE
mkdir -p "$debug_dir"
rm -f "$debug_dir/vz-idle-ready.json"
expected_index=$(mktemp "$debug_dir/vz-idle-index.XXXXXX")
rm -f "$expected_index"

expected_source_state() {
  local state=$1
  local unexpected
  GIT_INDEX_FILE="$expected_index" git -C "$source_dir" read-tree HEAD || return 1
  if [[ "$state" != pristine ]]; then
    GIT_INDEX_FILE="$expected_index" git -C "$source_dir" apply --cached "$phase_patch" || return 1
  fi
  if [[ "$state" == idle ]]; then
    GIT_INDEX_FILE="$expected_index" git -C "$source_dir" apply --cached "$idle_patch" || return 1
  fi
  GIT_INDEX_FILE="$expected_index" git -C "$source_dir" diff --quiet --exit-code || return 1
  unexpected=$(GIT_INDEX_FILE="$expected_index" git -C "$source_dir" ls-files --others --exclude-standard --exclude=/vz.test) || return 1
  [[ -z "$unexpected" ]]
}

if [[ -d "$source_dir/.git" ]]; then
  [[ $(git -C "$source_dir" rev-parse HEAD) == "$source_sha" ]]
  if expected_source_state idle; then
    git -C "$source_dir" apply --reverse "$idle_patch"
  elif expected_source_state phase || expected_source_state pristine; then
    :
  else
    echo 'Refusing source tree with unexpected tracked or untracked changes' >&2
    exit 1
  fi
fi

phase=phase-patch
"$diagnostic_root/scripts/prepare-vz.sh"

phase=idle-patch
cd "$source_dir"
expected_source_state phase || {
  echo 'Prepared source does not match the pinned phase patch' >&2
  exit 1
}
git apply --check "$idle_patch"
git apply "$idle_patch"
git apply --reverse --check "$idle_patch"

go_bin=${VZ_DIAGNOSTIC_GO_BIN:-/Users/runner/hostedtoolcache/go/1.26.7/x64/bin}
export PATH="$go_bin:$PATH"
export GOTOOLCHAIN=go1.26.8
[[ $(go env GOVERSION) == go1.26.8 ]]
phase=selector-tests
go test diagnostic_idle.go diagnostic_idle_test.go

phase=compile
rm -f "$binary"
go test -c -o "$binary" .
phase=startup
go run ./cmd/codesign "$binary" '-test.run=^$' -test.timeout=2m -test.v
phase=signature
codesign --verify --strict --verbose=2 "$binary"
codesign --display --entitlements - "$binary"

phase=manifest
expected_source_state idle || {
  echo 'Compiled source does not match the pinned phase and idle patches' >&2
  exit 1
}
python3 - "$source_dir" "$diagnostic_root" "$debug_dir/vz-idle-ready.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

source, diagnostic, destination = map(Path, sys.argv[1:])
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

record = {
    'source': '90ea0b8338dc8b482e315084f31e6ef6b194805f',
    'go': 'go1.26.8',
    'phasePatchSHA256': digest(diagnostic / 'probes/vz-phases.patch'),
    'idlePatchSHA256': digest(diagnostic / 'probes/vz-idle.patch'),
    'kernelSHA256': digest(source / 'testdata/Image'),
    'initrdSHA256': digest(source / 'testdata/initramfs.cpio.gz'),
    'binarySHA256': digest(source / 'vz.test'),
    'startupGuestExecution': False,
    'trialModes': ['baseline', 'poll', 'halt'],
}
destination.write_text(json.dumps(record, sort_keys=True) + '\n')
print(json.dumps(record, sort_keys=True))
PY
phase=ready
printf 'VZ_DIAGNOSTIC idle.ready binary=%s manifest=%s\n' "$binary" "$debug_dir/vz-idle-ready.json"
