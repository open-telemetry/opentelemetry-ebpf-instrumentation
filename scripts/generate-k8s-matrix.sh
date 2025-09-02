#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Generate simple k8s test matrix - one shard per test package directory
# Usage: ./scripts/generate-simple-k8s-matrix.sh

set -e

# Find all k8s test package directories (excluding common)
TEST_DIRS=$(find test/integration/k8s -name "*main_test.go" | grep -v common | sort | xargs dirname | xargs basename -a)

if [ -z "$TEST_DIRS" ]; then
    echo "ERROR: No k8s test directories found" >&2
    exit 1
fi

# Count directories
DIR_COUNT=$(echo "$TEST_DIRS" | wc -l | tr -d ' ')
echo "Total k8s test packages: $DIR_COUNT" >&2

# Generate matrix JSON
MATRIX_JSON='{"include":['
FIRST=true
SHARD_ID=0

for dir in $TEST_DIRS; do
    if [ "$FIRST" = "false" ]; then
        MATRIX_JSON+=","
    fi
    FIRST=false
    
    # Each shard runs all tests in its package directory
    MATRIX_JSON+="{\"id\":$SHARD_ID,\"description\":\"$dir\",\"test_pattern\":\"./test/integration/k8s/$dir/...\"}"
    
    echo "Shard $SHARD_ID: $dir" >&2
    
    SHARD_ID=$((SHARD_ID + 1))
done

MATRIX_JSON+=']}'
echo "$MATRIX_JSON"
