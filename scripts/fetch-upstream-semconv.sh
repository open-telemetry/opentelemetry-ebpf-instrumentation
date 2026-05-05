#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Pre-fetch the upstream OpenTelemetry semantic-conventions registry into
# `schemas/obi/.deps/` so weaver doesn't have to clone it on every container
# start. Without this, weaver's `live-check` resolves the dependency declared
# in `schemas/obi/manifest.yaml` over the network, which can take 30-60 s on
# a cold CI runner and trips the otelcol→weaver healthcheck dependency.
#
# Version is parsed out of `manifest.yaml` so there's a single source of
# truth for the pinned upstream semconv release.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/schemas/obi/manifest.yaml"
DEPS_DIR="$REPO_ROOT/schemas/obi/.deps"

# Extract the pinned upstream semconv version from the manifest. After this
# script has run once the manifest's `registry_path` points at the local
# `upstream-v<VERSION>` cache; before that it points at the upstream git
# URL with `@v<VERSION>`. Match either form.
VERSION=$(grep -oE '(upstream-v|@v)[0-9]+\.[0-9]+\.[0-9]+' "$MANIFEST" \
  | head -1 \
  | sed -E 's|.*v||')
if [ -z "$VERSION" ]; then
  echo "fetch-upstream-semconv: could not extract version from $MANIFEST" >&2
  exit 1
fi

TARGET="$DEPS_DIR/upstream-v$VERSION"
if [ -d "$TARGET/model" ]; then
  exit 0
fi

mkdir -p "$TARGET"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "fetch-upstream-semconv: fetching v$VERSION into $TARGET/model"
curl -fsSL "https://github.com/open-telemetry/semantic-conventions/archive/refs/tags/v${VERSION}.tar.gz" \
  | tar -xz -C "$TMPDIR" --strip-components=1 "semantic-conventions-${VERSION}/model"

mv "$TMPDIR/model" "$TARGET/model"
