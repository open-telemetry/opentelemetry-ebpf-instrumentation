#!/usr/bin/env bash
set -euo pipefail

# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

action_dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

MISE_ENABLE_TOOLS='' \
  GITHUB_OUTPUT="$tmp" bash "$action_dir/hash-tool-selector.sh"
empty=$(cut -d= -f2 "$tmp")
: > "$tmp"
MISE_ENABLE_TOOLS='go,clang,conda:llvm-tools,go:github.com/cilium/ebpf/cmd/bpf2go' \
  GITHUB_OUTPUT="$tmp" bash "$action_dir/hash-tool-selector.sh"
first=$(cut -d= -f2 "$tmp")
: > "$tmp"
MISE_ENABLE_TOOLS='go,clang,conda:llvm-tools,go:github.com/cilium/ebpf/cmd/bpf2go' \
  GITHUB_OUTPUT="$tmp" bash "$action_dir/hash-tool-selector.sh"
second=$(cut -d= -f2 "$tmp")
[[ "$first" == "$second" && "$empty" =~ ^[[:xdigit:]]{64}$ && "$first" =~ ^[[:xdigit:]]{64}$ ]]
: > "$tmp"
MISE_ENABLE_TOOLS='go' GITHUB_OUTPUT="$tmp" bash "$action_dir/hash-tool-selector.sh"
[[ "$first" != "$(cut -d= -f2 "$tmp")" ]]

: > "$tmp"
env -u MISE_ENABLE_TOOLS GITHUB_OUTPUT="$tmp" bash "$action_dir/hash-tool-selector.sh"
[[ "$(cut -d= -f2 "$tmp")" == "$empty" ]]

grep -Fq "runner.os == 'macOS'" "$action_dir/action.yml"
grep -Fq "if: \${{ inputs.cache-downloads == 'true' }}" "$action_dir/action.yml"
grep -Fq 'steps.tools.outputs.hash' "$action_dir/action.yml"

echo "setup-mise action helpers are consistent."
