#!/bin/bash
set -uo pipefail

if [[ -z ${RUNNER_TEMP:-} || ! -d $RUNNER_TEMP ]]; then
  printf '%s\n' 'RUNNER_TEMP must name an existing directory' >&2
  exit 2
fi

iterations=${1:-1}
case "$iterations" in
  1|2) ;;
  *) printf '%s\n' 'iteration count must be 1 or 2' >&2; exit 2 ;;
esac

debug_dir="$RUNNER_TEMP/debug"
mkdir -p "$debug_dir" || exit 1
log="$debug_dir/vz-pristine-output.log"
source_dir="$debug_dir/vz-pristine"
source_sha=90ea0b8338dc8b482e315084f31e6ef6b194805f

run() (
  set -euo pipefail
  checkout_created=0
  heartbeat_pid=
  finalize() {
    status=$?
    trap - EXIT
    set +e
    if [[ -n $heartbeat_pid ]]; then
      kill "$heartbeat_pid" 2>/dev/null
      wait "$heartbeat_pid" 2>/dev/null
    fi
    if [[ $checkout_created == 1 ]]; then
      printf 'FINAL_HEAD='
      git -C "$source_dir" rev-parse HEAD
      head_status=$?
      git -C "$source_dir" diff --exit-code
      worktree_status=$?
      git -C "$source_dir" diff --cached --exit-code
      index_status=$?
      if [[ $head_status != 0 || $worktree_status != 0 || $index_status != 0 ]] ||
         [[ $(git -C "$source_dir" rev-parse HEAD) != "$source_sha" ]]; then
        status=1
      fi
      printf 'FINAL_DIFF_WORKTREE=%s FINAL_DIFF_INDEX=%s\n' "$worktree_status" "$index_status"
    fi
    printf 'FINAL_EXIT=%s\n' "$status"
    exit "$status"
  }
  trap finalize EXIT
  [[ $(uname -s) == Darwin && $(uname -m) == x86_64 ]] || {
    printf '%s\n' 'macOS Intel required' >&2
    exit 1
  }
  if [[ -L $source_dir || ( -e $source_dir && ! -d $source_dir ) ]]; then
    printf '%s\n' 'source destination must be a directory, not a symlink' >&2
    exit 1
  fi
  if [[ -d $source_dir && -n $(find "$source_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    printf '%s\n' 'source destination is not empty' >&2
    exit 1
  fi
  mkdir -p "$source_dir"
  git -C "$source_dir" init
  checkout_created=1
  git -C "$source_dir" remote add origin https://github.com/Code-Hex/vz.git
  git -C "$source_dir" fetch --depth=1 origin "$source_sha"
  git -C "$source_dir" checkout --detach FETCH_HEAD
  [[ $(git -C "$source_dir" rev-parse HEAD) == "$source_sha" ]]
  cd "$source_dir"
  export GOTOOLCHAIN=go1.26.8
  go_version=$(go env GOVERSION)
  printf 'GO_VERSION=%s\n' "$go_version"
  [[ $go_version == go1.26.8 ]]
  make download_kernel
  printf '%s\n' \
    '336421443dbdba32f11762a8d9d4bd1db21abf9e722ea43ffffcd0478b4c11f3  testdata/Image' \
    '145bb21b8f66affc83da22f64b5597d8279b6a94529afbb39881361a7e28e2d6  testdata/initramfs.cpio.gz' |
    shasum -a 256 -c -
  go test -c -o vz.test .
  python3 -u -c 'import json,time; exec("while True:\n print(json.dumps({\"event\":\"host_heartbeat\",\"monotonic_ns\":time.monotonic_ns()}),flush=True)\n time.sleep(2)")' &
  heartbeat_pid=$!
  for ((iteration = 1; iteration <= iterations; iteration++)); do
    printf 'SUITE_ITERATION=%s\n' "$iteration"
    go run ./cmd/codesign "$PWD/vz.test" -test.timeout=3m -test.v
    printf 'SUITE_COMPLETED=%s\n' "$iteration"
  done
)

run 2>&1 | tee "$log"
statuses=("${PIPESTATUS[@]}")
if [[ ${statuses[0]} != 0 || ${statuses[1]} != 0 ]]; then
  exit 1
fi
