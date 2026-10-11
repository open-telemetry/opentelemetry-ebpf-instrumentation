#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Render the OBI telemetry reference (attributes + metrics + spans) from the
# semantic-convention registry under `schemas/obi/` into `site/docs/`, which is
# published to GitHub Pages by publish-schemas.yml.
#
# Rendering goes through `weaver registry resolve --v2` plus scripts/schema-docs.jq
# rather than `weaver registry generate` with a template set, so the pages stay a
# plain jq transform of the resolved registry.
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

# Resolution is judged by the payload rather than the exit code: weaver can exit
# non-zero on a diagnostic while still writing the complete resolved registry.
"$OCI_BIN" run --rm \
  -v "$REGISTRY:/obi-registry:ro,z" \
  -w /obi-registry \
  "$WEAVER_IMAGE" registry resolve \
    --registry /obi-registry \
    --v2 \
    --format json > "$resolved" 2>/dev/null || true

if ! jq -e '.registry.spans | length > 0' "$resolved" >/dev/null 2>&1; then
  echo "generate-schema-docs: weaver registry resolve produced no usable registry" >&2
  exit 1
fi

mkdir -p "$TARGET"
for page in readme attributes metrics spans; do
  case "$page" in
    readme) out="README.md" ;;
    *) out="$page.md" ;;
  esac
  jq -r --arg page "$page" -f "$JQ_PROGRAM" "$resolved" > "$TARGET/$out"
done

echo "generate-schema-docs: rendered README.md attributes.md metrics.md spans.md into $TARGET"
