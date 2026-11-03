#!/bin/bash
set -euo pipefail
[[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
  echo 'Run this probe build on the Intel macOS runner' >&2
  exit 1
}
cd "$(dirname "$0")/.."
output="${RUNNER_TEMP:?}/debug/probes"
mkdir -p "$output"
source_sha=$(shasum -a 256 probes/hypervisor.c | awk '{print $1}')
xcrun clang -arch x86_64 -mmacosx-version-min=12.0 -std=c11 \
  -Wall -Wextra -Werror -O1 -g "-DPROBE_SOURCE_SHA=\"$source_sha\"" \
  probes/hypervisor.c -framework Hypervisor -o "$output/hypervisor"
codesign --force --sign - --entitlements probes/hypervisor.entitlements "$output/hypervisor"
codesign --verify --strict --verbose=2 "$output/hypervisor"
codesign --display --entitlements - "$output/hypervisor"
printf 'PROBE_SOURCE_SHA=%s\n' "$source_sha"
