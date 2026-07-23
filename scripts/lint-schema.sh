#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validate the OBI semantic-convention registry under `schemas/obi/`.
#
# We capture `weaver registry check`'s JSON diagnostic stream and fail on any
# diagnostic that survives the allowlist in `lint-schema-filter.jq` (today:
# only the documented `dns.lookup.duration` DuplicateMetricName — see that
# file and schemas/obi/groups/dns.yaml for the rationale and the upstream
# weaver issue). `--future` promotes pending warnings (e.g. missing examples
# on string attributes) to errors so we catch them at PR time rather than in
# integration logs. Note that weaver exits non-zero when diagnostics exist,
# so a non-zero exit with parseable diagnostics on stdout is a lint finding,
# not an execution failure.
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
FILTER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lint-schema-filter.jq"

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
    --v2=true \
    --diagnostic-format json \
    --diagnostic-stdout 2>"$stderr") || rc=$?

# A failure without a parseable diagnostics array is an execution problem
# (image pull failure, bad mount, …), not a lint finding.
if [ "$rc" -ne 0 ] && ! printf '%s' "$out" | jq empty >/dev/null 2>&1; then
  echo "weaver registry check failed to run (exit $rc):" >&2
  cat "$stderr" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi

remaining=$(printf '%s' "${out:-[]}" | jq -f "$FILTER")

if [ "$remaining" != "[]" ]; then
  echo "weaver registry check produced diagnostics:" >&2
  printf '%s\n' "$remaining" >&2
  exit 1
fi
