#!/bin/bash
set -euo pipefail

[[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
  echo 'Run this preparation on the Intel macOS runner' >&2
  exit 1
}

cd "$(dirname "$0")/.."
patch_path="$PWD/probes/vz-phases.patch"
source_sha=90ea0b8338dc8b482e315084f31e6ef6b194805f
source_url=https://github.com/Code-Hex/vz.git
debug_dir="${RUNNER_TEMP:?}/debug"
source_dir="$debug_dir/vz"
binary="$source_dir/vz.test"
go_bin=${VZ_DIAGNOSTIC_GO_BIN:-/Users/runner/hostedtoolcache/go/1.26.7/x64/bin}
export PATH="$go_bin:$PATH"
export GOTOOLCHAIN=go1.26.8

phase=source
trap 'result=$?; printf "VZ_DIAGNOSTIC prepare phase=%s exitCode=%d\n" "$phase" "$result"' EXIT
mkdir -p "$source_dir"
if [[ ! -d "$source_dir/.git" ]]; then
  [[ -z $(ls -A "$source_dir") ]] || {
    echo 'Refusing to initialize a nonempty source directory' >&2
    exit 1
  }
  git -C "$source_dir" init --quiet
  git -C "$source_dir" remote add origin "$source_url"
fi
[[ $(git -C "$source_dir" remote get-url origin) == "$source_url" ]] || {
  echo 'Unexpected source remote' >&2
  exit 1
}
current_sha=$(git -C "$source_dir" rev-parse --verify HEAD 2>/dev/null || true)
if [[ "$current_sha" != "$source_sha" ]]; then
  [[ -z "$current_sha" ]] || {
    echo 'Source directory is already on a different commit' >&2
    exit 1
  }
  git -C "$source_dir" fetch --depth=1 origin "$source_sha"
  git -C "$source_dir" checkout --detach FETCH_HEAD
fi
[[ $(git -C "$source_dir" rev-parse HEAD) == "$source_sha" ]]
printf 'VZ_DIAGNOSTIC source=%s patch=' "$source_sha"
shasum -a 256 "$patch_path"

phase=patch
cd "$source_dir"
if git apply --reverse --check "$patch_path" 2>/dev/null; then
  echo 'VZ_DIAGNOSTIC patch already applied'
else
  git apply --check "$patch_path"
  git apply "$patch_path"
fi

phase=toolchain
go version
go env GOVERSION > "$debug_dir/vz-go-version.txt"
[[ $(cat "$debug_dir/vz-go-version.txt") == go1.26.8 ]]
export VZ_DIAGNOSTIC_GO="$(cat "$debug_dir/vz-go-version.txt")"
export VZ_DIAGNOSTIC_CASE=startup
export VZ_DIAGNOSTIC_TARGET=startup
export VZ_DIAGNOSTIC_COUNT=0
export VZ_DIAGNOSTIC_PROCESS_NUMBER=1

phase=kernel
make download_kernel
[[ -s testdata/Image && -s testdata/initramfs.cpio.gz ]]
shasum -a 256 testdata/Image testdata/initramfs.cpio.gz

phase=compile
go test -c -o "$binary" .
phase=startup
go run ./cmd/codesign "$binary" '-test.run=^$' -test.timeout=2m -test.v
phase=signature
codesign --verify --strict --verbose=2 "$binary"
codesign --display --entitlements - "$binary"
shasum -a 256 "$binary"
phase=ready
printf 'VZ_DIAGNOSTIC ready binary=%s go=%s\n' "$binary" "$VZ_DIAGNOSTIC_GO"
