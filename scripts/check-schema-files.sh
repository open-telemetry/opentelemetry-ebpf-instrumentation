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

numeric_identifier='0|[1-9][0-9]*'
prerelease_identifier="($numeric_identifier|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)"
build_identifier='[0-9a-zA-Z-]+'
schema_version_pattern="($numeric_identifier)\.($numeric_identifier)\.($numeric_identifier)"
release_version_pattern="$schema_version_pattern(-$prerelease_identifier(\.$prerelease_identifier)*)?(\+$build_identifier(\.$build_identifier)*)?"

shopt -s nullglob
count=0
for file in "$SCHEMA_DIR"/*; do
	version="$(basename "$file")"

	echo "$version" | grep -Eq "^$schema_version_pattern$" \
		|| fail "$file: name is not a MAJOR.MINOR.PATCH version"

	format="$(grep -E '^file_format:' "$file" | head -1 | sed 's/^file_format:[[:space:]]*//')"
	[ "$format" = "1.1.0" ] || fail "$file: file_format must be 1.1.0 (got '${format:-<missing>}')"

	url="$(grep -E '^schema_url:' "$file" | head -1 | sed 's/^schema_url:[[:space:]]*//')"
	expected="$BASE_URL/$version"
	[ "$url" = "$expected" ] || fail "$file: schema_url '$url' does not match served URL '$expected'"

	grep -Fxq "  $version:" "$file" \
		|| fail "$file: versions: block does not contain an entry for $version"

	while IFS= read -r entry; do
		echo "$entry" | grep -Eq "^$schema_version_pattern$" \
			|| fail "$file: versions: entry '$entry' is not a MAJOR.MINOR.PATCH version"
	done < <(awk '/^versions:/{v=1; next} v && /^  [^[:space:]]+:/ {key=$1; sub(/:$/, "", key); print key}' "$file")

	count=$((count + 1))
done

[ "$count" -gt 0 ] || fail "no schema files found under $SCHEMA_DIR"

# Prereleases retain a published stable schema; stable releases name their own
# version. Both emitted and registry URLs must identify the same published file.
version="$(awk '/^  obi:/{o=1} o&&/version:/{v=$2; sub(/^v/,"",v); print v; exit}' "$ROOT/versions.yaml")"
emitted_url="$(awk -F '"' '/^var OBISchemaURL = /{print $2; exit}' "$SCHEMA_VERSION_FILE")"
manifest_url="$(awk '/^schema_url:/{print $2; exit}' "$MANIFEST")"
emitted="${emitted_url#"$BASE_URL/"}"

[ -n "$version" ] || fail "could not read the obi version from versions.yaml"
echo "$version" | grep -Eq "^$release_version_pattern$" || fail "versions.yaml obi version '$version' is invalid"
version="${version%%+*}"
echo "$emitted" | grep -Eq "^$schema_version_pattern$" || fail "OBISchemaURL must name a stable MAJOR.MINOR.PATCH version"
[ "$manifest_url" = "$emitted_url" ] || fail "manifest schema_url ($manifest_url) does not match OBISchemaURL ($emitted_url)"
[ -f "$SCHEMA_DIR/$emitted" ] || fail "site/schemas/obi/$emitted is not published (would 404)"
if [[ "$version" != *-* ]]; then
	[ "$emitted" = "$version" ] || fail "OBISchemaURL ($emitted) does not match the versions.yaml version ($version)"
fi

echo "check-schema-files: OK ($count published, release = $version, schema_url = $emitted)"
