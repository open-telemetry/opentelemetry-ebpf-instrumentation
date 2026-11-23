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

workflow="$action_dir/../../workflows/pull_request.yml"
[[ $(grep -Fc 'GOBIN: ${{ runner.temp }}/ocb-bin' "$workflow") -eq 2 ]]
grep -Fq 'go install go.opentelemetry.io/collector/cmd/builder@"${OCB_VERSION}"' "$workflow"
grep -Fq 'mkdir -p "$GOBIN"' "$workflow"
grep -Fq '"$GOBIN/builder" --config ./builder-config.yaml' "$workflow"

fixture_dir=$(mktemp -d)
trap 'rm -f "$tmp"; rm -rf "$fixture_dir"' EXIT
mkdir -p "$fixture_dir/fake-bin"
cat > "$fixture_dir/fake-bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == install ]]
cat > "$GOBIN/builder" <<'BUILDER'
#!/usr/bin/env bash
printf '%s\n' "$@"
BUILDER
chmod +x "$GOBIN/builder"
EOF
chmod +x "$fixture_dir/fake-bin/go"
output=$(PATH="$fixture_dir/fake-bin:$PATH" GOBIN="$fixture_dir/ocb bin" bash -c '
  mkdir -p "$GOBIN"
  go install go.opentelemetry.io/collector/cmd/builder@v0.163.0
  "$GOBIN/builder" --config ./builder-config.yaml
')
[[ "$output" == $'--config\n./builder-config.yaml' ]]
