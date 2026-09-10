#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Render the OBI telemetry reference (attributes + metrics) from the
# semantic-convention registry under `schemas/obi/` into `site/docs/`, which is
# published to GitHub Pages by publish-schemas.yml.
#
# Rendering goes through `weaver registry resolve` plus scripts/schema-docs.jq
# rather than `weaver registry generate`, because generation aborts on the
# duplicate-attribute diagnostics produced by OBI's `x.obi.*` override groups —
# the same expected findings scripts/lint-schema-filter.jq allowlists for
# `registry check`. Resolve still emits the complete resolved registry alongside
# those diagnostics, so we filter and render it ourselves. This can move to
# `registry generate` with a template set once weaver defines override semantics
# between a registry and its dependencies
# (https://github.com/open-telemetry/weaver/issues/1578).
#
# Those same duplicates make resolution non-deterministic for the overridden
# attributes: weaver may pick either the upstream or the OBI description between
# runs, so regenerating can produce a small diff with no registry change. That is
# why the output is not verified byte-for-byte in CI.
#
# The registry declares the upstream semconv registry as a dependency, resolved
# from the prefetched copy under schemas/obi/.deps (see
# scripts/fetch-upstream-semconv.sh). Weaver resolves that path relative to the
# working directory, so the container runs with the registry as its cwd.
#
# Usage: generate-schema-docs.sh <oci-bin> <weaver-image> [output-dir]
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $(basename "$0") <oci-bin> <weaver-image> [output-dir]" >&2
  exit 2
fi

OCI_BIN="$1"
WEAVER_IMAGE="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="$ROOT/schemas/obi"
TARGET="${3:-$ROOT/site/docs}"
JQ_PROGRAM="$ROOT/scripts/schema-docs.jq"

resolved=$(mktemp)
trap 'rm -f "$resolved"' EXIT

# `--include-unreferenced` keeps OBI's standalone override and marker groups in
# the resolution. Weaver exits non-zero because of the expected duplicate
# diagnostics, so validity is judged by the payload, not the exit code.
"$OCI_BIN" run --rm \
  -v "$REGISTRY:/obi-registry:ro,z" \
  -w /obi-registry \
  "$WEAVER_IMAGE" registry resolve \
    --registry /obi-registry \
    --include-unreferenced \
    --format json > "$resolved" 2>/dev/null || true

if ! jq -e '.groups | length > 0' "$resolved" >/dev/null 2>&1; then
  echo "generate-schema-docs: weaver registry resolve produced no usable registry" >&2
  exit 1
fi

mkdir -p "$TARGET"
for page in readme attributes metrics; do
  case "$page" in
    readme) out="README.md" ;;
    *) out="$page.md" ;;
  esac
  jq -r --arg page "$page" -f "$JQ_PROGRAM" "$resolved" > "$TARGET/$out"
done

echo "generate-schema-docs: rendered README.md attributes.md metrics.md into $TARGET"
