#!/bin/bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]]
[[ "${GITHUB_REPOSITORY:-}" == Code-Hex/vz-ci-test ]]
[[ "${GITHUB_REF:-}" == refs/heads/main ]]
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]]
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]
[[ "$(uname -s)" == Darwin && "$(uname -m)" == x86_64 ]]

reader_dir="${RUNNER_TEMP:?}/debug/bin"
archive="${RUNNER_TEMP}/debug/ipsw-reader.tar.gz"
mkdir -p "$reader_dir"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 90 \
  https://github.com/blacktop/ipsw/releases/download/v3.1.730/ipsw_3.1.730_macOS_x86_64.tar.gz \
  --output "$archive"
printf '%s  %s\n' c05011d005392db90ef6f7ea95ed7d956fe3ffd695f015ad8f9b2557752383e8 "$archive" | shasum -a 256 --check --status
tar -xzf "$archive" -C "$reader_dir" ipsw
[[ -f "$reader_dir/ipsw" && ! -L "$reader_dir/ipsw" && -x "$reader_dir/ipsw" ]]
rm "$archive"
