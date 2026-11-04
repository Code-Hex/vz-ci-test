#!/bin/bash
set -uo pipefail

if [[ -z ${RUNNER_TEMP:-} || ! -d $RUNNER_TEMP ]]; then
  printf '%s\n' 'RUNNER_TEMP must name an existing directory' >&2
  exit 2
fi

debug_dir="$RUNNER_TEMP/debug"
mkdir -p "$debug_dir" || exit 1
log="$debug_dir/wait-linux-preparation.log"
source_dir="$debug_dir/vz-pristine"
source_sha=90ea0b8338dc8b482e315084f31e6ef6b194805f

prepare() (
  set -euo pipefail
  checkout_created=0
  finalize() {
    status=$?
    trap - EXIT
    set +e
    if [[ $checkout_created == 1 ]]; then
      final_head=$(git -C "$source_dir" rev-parse HEAD)
      head_status=$?
      printf 'FINAL_HEAD=%s\n' "$final_head"
      git -C "$source_dir" diff --exit-code
      worktree_status=$?
      git -C "$source_dir" diff --cached --exit-code
      index_status=$?
      printf 'FINAL_DIFF_WORKTREE=%s FINAL_DIFF_INDEX=%s\n' "$worktree_status" "$index_status"
      if [[ $head_status != 0 || $worktree_status != 0 || $index_status != 0 ||
            $final_head != "$source_sha" ]]; then
        status=1
      fi
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
  export GOTOOLCHAIN=go1.27.3
  go_version=$(go env GOVERSION)
  printf 'GO_VERSION=%s\n' "$go_version"
  [[ $go_version == go1.27.3 ]]
  make download_kernel
  printf '%s\n' \
    '336421443dbdba32f11762a8d9d4bd1db21abf9e722ea43ffffcd0478b4c11f3  testdata/Image' \
    '145bb21b8f66affc83da22f64b5597d8279b6a94529afbb39881361a7e28e2d6  testdata/initramfs.cpio.gz' |
    shasum -a 256 -c -
  go test -c -o vz.test .
  go run ./cmd/codesign "$PWD/vz.test" -test.run '^$'
  codesign --verify --strict --verbose=2 "$PWD/vz.test"
  shasum -a 256 "$PWD/vz.test"
  printf 'VZ_TEST_BINARY=%s\n' "$PWD/vz.test"
)

prepare 2>&1 | tee "$log"
statuses=("${PIPESTATUS[@]}")
if [[ ${statuses[0]} != 0 || ${statuses[1]} != 0 ]]; then
  exit 1
fi
