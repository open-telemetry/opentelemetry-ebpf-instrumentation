#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Compare importable, non-command root-module packages. The root module's
# published Go API is stable under VERSIONING.md; internal packages and build
# tooling are not part of this check. Collector is a separate module.
# Generated BPF files in each checkout must match that checkout's revision.
# Run locally with: GITHUB_STEP_SUMMARY=/tmp/api-summary ./scripts/check-go-api-compatibility.sh ./base ./head
readonly apidiff_version="v0.0.0-20261124000051-d6646c509b6d"
if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base-checkout> <head-checkout>" >&2
  exit 2
fi
base_dir="$(cd "$1" && pwd)"
readonly base_dir
head_dir="$(cd "$2" && pwd)"
readonly head_dir
export GOWORK=off
tmp="$(mktemp -d)"
readonly tmp
trap 'rm -rf "$tmp"' EXIT

expected_module='go.opentelemetry.io/obi'
for module_dir in "$base_dir" "$head_dir"; do
  if [[ ! -f "$module_dir/go.mod" ]]; then
    echo "missing go.mod in $module_dir" >&2
    exit 1
  fi
  module_path="$(awk '$1 == "module" { print $2; exit }' "$module_dir/go.mod")"
  if [[ "$module_path" != "$expected_module" ]]; then
    echo "unexpected module path in $module_dir: $module_path" >&2
    exit 1
  fi
done

GOBIN="$tmp/bin" go install "golang.org/x/exp/cmd/apidiff@$apidiff_version"

package_list() {
  (cd "$1" && go list -f '{{if ne .Name "main"}}{{.ImportPath}}{{end}}' ./... \
    | awk '$0 != "" && $0 !~ /(^|\/)internal(\/|$)/ && $0 !~ /^go\.opentelemetry\.io\/obi\/(cmd|scripts|examples|tools|bpf)(\/|$)/' \
    | LC_ALL=C sort -u)
}

package_list "$base_dir" > "$tmp/base-packages"
package_list "$head_dir" > "$tmp/head-packages"
LC_ALL=C comm -12 "$tmp/base-packages" "$tmp/head-packages" > "$tmp/shared-packages"
LC_ALL=C comm -13 "$tmp/base-packages" "$tmp/head-packages" > "$tmp/added-packages"
LC_ALL=C comm -23 "$tmp/base-packages" "$tmp/head-packages" > "$tmp/removed-packages"

echo '## Public Go API compatibility (report only)' >> "$GITHUB_STEP_SUMMARY"
base_revision="$(git -C "$base_dir" rev-parse --short HEAD 2>/dev/null || echo unknown)"
head_revision="$(git -C "$head_dir" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "Compared pull request base $base_revision with tested head $head_revision (Linux $(uname -m)). Each checkout must contain generated BPF files from its matching revision. Scope is publicly importable root-module packages; internal packages, commands, and build tooling are excluded. Collector is a separate module. This report-only source API check is not a definitive compatibility guarantee." >> "$GITHUB_STEP_SUMMARY"

if [[ -s "$tmp/added-packages" ]]; then
  while IFS= read -r package; do
    printf '#### %s\n\n- New public package\n\n' "$package" >> "$tmp/additions"
  done < "$tmp/added-packages"
fi

if [[ -s "$tmp/removed-packages" ]]; then
  {
    echo '#### Removed public packages'
    echo
    sed 's/^/    /' "$tmp/removed-packages"
    echo
  } >> "$tmp/incompatibilities"
fi

index=0
while IFS= read -r import_path; do
  [[ -n "$import_path" ]] || continue
  index=$((index + 1))
  (cd "$base_dir" && "$tmp/bin/apidiff" -w "$tmp/$index.old" "$import_path")
  (cd "$head_dir" && "$tmp/bin/apidiff" -w "$tmp/$index.new" "$import_path")
  if ! "$tmp/bin/apidiff" "$tmp/$index.old" "$tmp/$index.new" > "$tmp/$index.diff"; then
    echo "apidiff failed for $import_path" >&2
    exit 1
  fi
  awk -v package="$import_path" -v incompatible="$tmp/$index.incompatible" -v additions="$tmp/additions" '
    /^Incompatible changes:$/ { section="incompatible"; next }
    /^Compatible changes:$/ { section="compatible"; next }
    section == "incompatible" && /^- / {
      if (!incompatible_header) { print "#### " package >> incompatible; incompatible_header=1 }
      print $0 >> incompatible
    }
    section == "compatible" && /^- / && /: added$/ {
      if (!addition_header) { print "#### " package "\n" >> additions; addition_header=1 }
      print $0 >> additions
    }
  ' "$tmp/$index.diff"
  if [[ -s "$tmp/$index.incompatible" ]]; then cat "$tmp/$index.incompatible" >> "$tmp/incompatibilities"; fi
done < "$tmp/shared-packages"

emit_annotation() {
  local level="$1" title="$2" message="$3"
  message="${message//'%'/'%25'}"
  message="${message//$'\r'/'%0D'}"
  message="${message//$'\n'/'%0A'}"
  printf '::%s title=%s::%s\n' "$level" "$title" "$message"
}

if [[ -s "$tmp/additions" ]]; then
  echo '### Public API additions' >> "$GITHUB_STEP_SUMMARY"
  cat "$tmp/additions" >> "$GITHUB_STEP_SUMMARY"
  additions_report="$(head -c 2800 "$tmp/additions")"
  [[ $(wc -c < "$tmp/additions") -le 2800 ]] || additions_report+=$'\n[report truncated]'
  emit_annotation notice obi-go-api-additions-report "$additions_report"
fi

if [[ -s "$tmp/incompatibilities" ]]; then
  echo '### Potential incompatibilities' >> "$GITHUB_STEP_SUMMARY"
  cat "$tmp/incompatibilities" >> "$GITHUB_STEP_SUMMARY"
  report="$(head -c 2800 "$tmp/incompatibilities")"
  [[ $(wc -c < "$tmp/incompatibilities") -le 2800 ]] || report+=$'\n[report truncated]'
  emit_annotation warning obi-go-api-compatibility-report "$report"
else
  echo 'No incompatible API changes detected in the compared packages.' >> "$GITHUB_STEP_SUMMARY"
  emit_annotation notice obi-go-api-compatibility-report 'No incompatible API changes detected.'
fi
