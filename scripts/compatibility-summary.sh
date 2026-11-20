#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

: "${ARCH:?ARCH is required}"
: "${COMPARE_OUTCOME?COMPARE_OUTCOME must be set}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

report="${1:-testoutput/compatibility.json}"
report_valid=false
{
  printf '## Go API compatibility: linux/%s (advisory)\n\n' "$ARCH"
  printf 'Only the public root-module Go API is checked. Enforcement is not enabled.\n\n'
  if [[ ! -s "$report" ]]; then
    printf '**INCOMPLETE:** no report was produced; check prerequisite jobs and logs.\n'
  elif ! jq -e '.format_version == 2 and (.findings | type == "array") and (.existing_findings | type == "array") and (.unclassified_changes | type == "array") and (.existing_unclassified_changes | type == "array") and (.baselines | type == "array") and (.required_release | IN("patch", "minor", "major", "incomplete"))' "$report" >/dev/null; then
    printf '**INCOMPLETE:** the report is malformed; check the comparison logs.\n'
  elif jq -e '.error != null' "$report" >/dev/null; then
    printf '**INCOMPLETE:** the comparison could not be completed.\n\n'
    jq -r '.error' "$report"
  else
    report_valid=true
    jq -r '
      "Minimum Go API release class: **\(.required_release)**\n",
      (if (.findings | length) == 0
       then "No incompatible public Go API changes introduced by this PR."
       else "**Incompatible API changes introduced: \(.findings | length)**. See the report for affected declarations."
       end)
    ' "$report"
  fi
} >> "$GITHUB_STEP_SUMMARY"
if [[ "$COMPARE_OUTCOME" != success ]]; then
  printf '::warning::Go API compatibility is advisory; the comparison is incomplete or this PR introduces an incompatibility. See the report and logs.\n'
fi
if [[ "$report_valid" == true ]] && jq -e '.error == null and (.baselines | length > 0)' "$report" >/dev/null; then
  printf 'verified=true\n' >> "$GITHUB_OUTPUT"
fi
