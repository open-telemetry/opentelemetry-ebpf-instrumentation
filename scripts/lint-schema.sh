#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validate the OBI semantic-convention registry under `schemas/obi/`.
#
# `weaver registry check` always exits 0, even on hard errors, so we instead
# capture its JSON diagnostic stream: an empty array means the registry is
# clean. `--future` promotes pending warnings (e.g. missing examples on
# string attributes) to errors so we catch them at PR time rather than in
# integration logs.
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

if ! out=$($OCI_BIN run --rm \
  -v "${REGISTRY_PATH}:/obi-registry:ro" \
  -w /obi-registry \
  "$WEAVER_IMAGE" registry check \
    --registry /obi-registry \
    --include-unreferenced \
    --future \
    --diagnostic-format json \
    --diagnostic-stdout 2>"$stderr"); then
  echo "weaver registry check failed to run:" >&2
  cat "$stderr" >&2
  exit 1
fi

if [ -n "$out" ] && [ "$out" != "[]" ]; then
  echo "weaver registry check produced diagnostics:" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi
