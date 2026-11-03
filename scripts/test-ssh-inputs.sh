#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/key"
key=$(cat "$test_dir/key.pub")
check() {
  local expected=$1 public_key=$2 duration=$3
  local actual=0
  SSH_PUBLIC_KEY="$public_key" DURATION_MINUTES="$duration" \
    bash scripts/validate-ssh-inputs.sh >"$test_dir/output" 2>&1 || actual=$?
  if [[ "$expected" == accept && "$actual" != 0 ]] || \
     [[ "$expected" == reject && "$actual" == 0 ]]; then
    cat "$test_dir/output" >&2
    echo "Unexpected validation result: $expected, duration=$duration, exit=$actual" >&2
    exit 1
  fi
}
check accept "$key" 1
check accept "$key" 30
check accept "$key" 60
check reject '' 30
check reject "${key}"$'\n'"${key}" 30
check reject "${key}"$'\r' 30
check reject "command=\"id\" $key" 30
check reject 'ssh-ed25519 AAAA' 30
check reject "ssh-rsa ${key#* }" 30
for duration in 0 61 -1 1.5 01 '' '$(id)'; do
  check reject "$key" "$duration"
done
echo 'SSH input checks passed'
