#!/bin/bash
set -euo pipefail
[[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
  echo 'Run this sampler build on the Intel macOS runner' >&2
  exit 1
}
cd "$(dirname "$0")/.."
output="${RUNNER_TEMP:?}/debug/probes"
mkdir -p "$output"
xcrun clang -arch x86_64 -mmacosx-version-min=12.0 -std=c11 \
  -Wall -Wextra -Werror -O1 -g probes/pc_sampler.c -o "$output/pc-sampler"
shasum -a 256 probes/pc_sampler.c probes/pc_sampler.d "$output/pc-sampler"
