#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validate the OBI semantic-convention registry under `schemas/obi/`.
#
# We capture `weaver registry check`'s JSON diagnostic stream: an empty array
# (after filtering the documented allowlist below) means the registry is
# clean. `--future` promotes pending warnings (e.g. missing examples on
# string attributes) to errors so we catch them at PR time rather than in
# integration logs. Note that weaver exits non-zero when diagnostics exist,
# so a non-zero exit with parseable diagnostics on stdout is a lint finding,
# not an execution failure.
#
# Allowlisted diagnostics:
#
# - DuplicateMetricName: the OBI registry deliberately re-declares upstream
#   metrics (via `extends` under a distinct group id) to override attribute
#   requirement levels — e.g. schemas/obi/groups/dns.yaml relaxes
#   `dns.question.name` to opt_in. weaver has no first-class override
#   mechanism between a registry and its dependencies yet, and no CLI flag
#   to suppress this check: `registry check` flags the metric-name duplicate
#   while `registry live-check` resolves it in the local group's favor.
#   (Reusing the upstream group id instead is worse: check then fires
#   DuplicateGroupId AND DuplicateMetricName, and live-check resolves the
#   tie in the dependency's favor, discarding the override.) Ignored until
#   weaver defines override semantics — tracked in
#   https://github.com/open-telemetry/weaver/issues/1578. See the comment
#   in groups/dns.yaml.
#
# Usage: lint-schema.sh <oci-bin> <weaver-image> <registry-host-path>
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $(basename "$0") <oci-bin> <weaver-image> <registry-host-path>" >&2
  exit 2
fi

OCI_BIN="$1"
WEAVER_IMAGE="$2"
REGISTRY_PATH="$3"

stderr=$(mktemp)
trap 'rm -f "$stderr"' EXIT

rc=0
out=$($OCI_BIN run --rm \
  -v "${REGISTRY_PATH}:/obi-registry:ro" \
  -w /obi-registry \
  "$WEAVER_IMAGE" registry check \
    --registry /obi-registry \
    --include-unreferenced \
    --future \
    --diagnostic-format json \
    --diagnostic-stdout 2>"$stderr") || rc=$?

# A failure without a parseable diagnostics array is an execution problem
# (image pull failure, bad mount, …), not a lint finding.
if [ "$rc" -ne 0 ] && ! printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
  echo "weaver registry check failed to run (exit $rc):" >&2
  cat "$stderr" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi

remaining=$(printf '%s' "${out:-[]}" | python3 -c '
import json
import sys

def allowlisted(d):
    return "DuplicateMetricName" in d.get("error", {})

diags = json.load(sys.stdin)
print(json.dumps([d for d in diags if not allowlisted(d)], indent=2))
')

if [ "$remaining" != "[]" ]; then
  echo "weaver registry check produced diagnostics:" >&2
  printf '%s\n' "$remaining" >&2
  exit 1
fi
