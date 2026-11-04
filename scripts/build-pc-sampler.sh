#!/bin/bash
set -euo pipefail
[[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
  echo 'Run this sampler build on the Intel macOS runner' >&2
  exit 1
}
expected_uuid=87453B1D-A163-31FA-B33B-0FB4BE78E6E8
[[ $(sysctl -n kern.uuid) == "$expected_uuid" &&
   $(xcrun dwarfdump --uuid /System/Library/Kernels/kernel | awk '{print $2}') == "$expected_uuid" ]] || {
  echo 'Wait frame offsets require the validated kernel UUID' >&2
  exit 1
}
cd "$(dirname "$0")/.."
output="${RUNNER_TEMP:?}/debug/probes"
mkdir -p "$output"
xcrun clang -arch x86_64 -mmacosx-version-min=12.0 -std=c11 \
  -Wall -Wextra -Werror -O1 -g probes/pc_sampler.c -o "$output/pc-sampler"
shasum -a 256 probes/pc_sampler.c probes/pc_sampler.d probes/wait_snapshot.h "$output/pc-sampler"
