#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validate the published OBI telemetry schema files and their consistency with
# the emitted schema_url constant and the weaver registry manifest.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA_DIR="${1:-$ROOT/site/schemas/obi}"
BASE_URL="https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi"
SCHEMA_VERSION_FILE="$ROOT/pkg/export/attributes/names/schema_version.go"
MANIFEST="$ROOT/schemas/obi/manifest.yaml"

fail() {
	echo "check-schema-files: $1" >&2
	exit 1
}

url_version() { grep -oE 'schemas/obi/[0-9]+\.[0-9]+\.[0-9]+' "$1" | head -1 | sed 's#.*/##'; }

shopt -s nullglob
count=0
for file in "$SCHEMA_DIR"/*; do
	version="$(basename "$file")"

	echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
		|| fail "$file: name is not a MAJOR.MINOR.PATCH version"

	format="$(grep -E '^file_format:' "$file" | head -1 | sed 's/^file_format:[[:space:]]*//')"
	[ "$format" = "1.1.0" ] || fail "$file: file_format must be 1.1.0 (got '${format:-<missing>}')"

	url="$(grep -E '^schema_url:' "$file" | head -1 | sed 's/^schema_url:[[:space:]]*//')"
	expected="$BASE_URL/$version"
	[ "$url" = "$expected" ] || fail "$file: schema_url '$url' does not match served URL '$expected'"

	grep -Eq "^  $version:" "$file" \
		|| fail "$file: versions: block does not contain an entry for $version"

	count=$((count + 1))
done

[ "$count" -gt 0 ] || fail "no schema files found under $SCHEMA_DIR"

# Release-driven consistency: the emitted schema_url and the manifest must name
# the versions.yaml version, and that version must be published (so it resolves).
version="$(awk '/^  obi:/{o=1} o&&/version:/{v=$2; sub(/^v/,"",v); print v; exit}' "$ROOT/versions.yaml")"
emitted="$(url_version "$SCHEMA_VERSION_FILE")"
manifest_v="$(url_version "$MANIFEST")"

[ -n "$version" ] || fail "could not read the obi version from versions.yaml"
[ -f "$SCHEMA_DIR/$version" ] || fail "versions.yaml is $version but site/schemas/obi/$version is not published (would 404)"
[ "$emitted" = "$version" ] || fail "OBISchemaURL ($emitted) does not match the versions.yaml version ($version)"
[ "$manifest_v" = "$version" ] || fail "manifest schema_url ($manifest_v) does not match the versions.yaml version ($version)"

echo "check-schema-files: OK ($count published, schema_url = $version)"
