#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Generate test matrix - one shard per test directory
# Usage: ./scripts/generate-dir-matrix.sh [search_dir] [exclude_pattern]

set -euo pipefail

SEARCH_DIR="${1:-internal/test/integration/k8s}"
EXCLUDE_PATTERN="${2:-common}"

declare -A seen_dirs=()
declare -a test_dirs=()

while IFS= read -r -d '' test_file; do
    if [[ -n "$EXCLUDE_PATTERN" && "$test_file" =~ $EXCLUDE_PATTERN ]]; then
        continue
    fi

    dir=$(basename -- "$(dirname -- "$test_file")")
    if [[ ! "$dir" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo "ERROR: Invalid test directory basename '$dir' in $SEARCH_DIR; only [A-Za-z0-9_-] are allowed" >&2
        exit 1
    fi

    if [[ -z "${seen_dirs[$dir]+x}" ]]; then
        seen_dirs["$dir"]=1
        test_dirs+=("$dir")
    fi
done < <(find "$SEARCH_DIR" -name "*_test.go" -print0 | sort -z)

if [ "${#test_dirs[@]}" -eq 0 ]; then
    echo "ERROR: No test directories found in $SEARCH_DIR" >&2
    exit 1
fi

mapfile -t sorted_dirs < <(printf '%s\n' "${test_dirs[@]}" | sort)

DIR_COUNT="${#sorted_dirs[@]}"
echo "Total test packages: $DIR_COUNT" >&2

MATRIX_JSON='{"include":['
FIRST=true
SHARD_ID=0

for dir in "${sorted_dirs[@]}"; do
    if [ "$FIRST" = "false" ]; then
        MATRIX_JSON+=","
    fi
    FIRST=false

    MATRIX_JSON+="{\"id\":$SHARD_ID,\"basename\":\"$dir\",\"test_pattern\":\"./$SEARCH_DIR/$dir/...\"}"

    echo "Shard $SHARD_ID: $dir" >&2

    SHARD_ID=$((SHARD_ID + 1))
done

MATRIX_JSON+=']}'
echo "$MATRIX_JSON"
