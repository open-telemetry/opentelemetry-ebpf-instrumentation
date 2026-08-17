#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Generate standard test matrix with configurable partitions
# Usage: ./scripts/generate-integration-matrix.sh [search_dir] [partitions] [test_pattern]

set -euo pipefail
shopt -s lastpipe

SCRIPT_DIR="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)"
SEARCH_DIR="${1:-internal/test/integration}"
PARTITIONS="${2:-5}"
TEST_PATTERN="${3:-Test}"
WEIGHTS_FILE="${OBI_INTEGRATION_TEST_WEIGHTS_FILE:-$SCRIPT_DIR/integration-test-weights.generated.json}"

required_commands=(awk find grep sed sort tr)
missing_commands=()
for command_name in "${required_commands[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        missing_commands+=("$command_name")
    fi
done
if (( ${#missing_commands[@]} > 0 )); then
    printf 'ERROR: missing required commands: %s\n' "${missing_commands[*]}" >&2
    exit 1
fi

if [[ ! "$PARTITIONS" =~ ^[1-9][0-9]*$ ]]; then
    printf "ERROR: partitions must be a positive integer, got '%s'\n" "$PARTITIONS" >&2
    exit 1
fi
if [[ ! -d "$SEARCH_DIR" ]]; then
    printf "ERROR: search directory not found: '%s'\n" "$SEARCH_DIR" >&2
    exit 1
fi
if [[ "$TEST_PATTERN" == *$'\n'* || "$TEST_PATTERN" == *$'\r'* ]]; then
    echo "ERROR: test pattern must not contain newline or carriage return" >&2
    exit 1
fi

declare -a test_files=()
if ! find "$SEARCH_DIR" -maxdepth 1 -type f -name "*_test.go" -print0 | LC_ALL=C sort -z | mapfile -d '' -t test_files; then
    echo "ERROR: failed to discover test files" >&2
    exit 1
fi

if (( ${#test_files[@]} == 0 )); then
    echo "ERROR: No test files found" >&2
    exit 1
fi

declare -a test_names=()
if grep -hE "^func $TEST_PATTERN" "${test_files[@]}" \
    | sed 's/^func \([^(]*\).*/\1/' \
    | LC_ALL=C sort -u \
    | mapfile -t test_names; then
    :
else
    extraction_status=("${PIPESTATUS[@]}")
    if (( extraction_status[0] == 1 && extraction_status[1] == 0 && extraction_status[2] == 0 && extraction_status[3] == 0 )); then
        printf "ERROR: No tests matching '%s' found in '%s'\n" "$TEST_PATTERN" "$SEARCH_DIR" >&2
    else
        printf 'ERROR: failed to extract test names (grep=%d sed=%d sort=%d read=%d)\n' "${extraction_status[@]}" >&2
    fi
    exit 1
fi

# Look up weights and assign tests to shards using LPT (Longest Processing Time)
# bin packing: sort tests by weight descending, assign each to the lightest shard.
if [[ -f "$WEIGHTS_FILE" ]] && command -v jq >/dev/null 2>&1; then
    if ! jq -e -s '
        length == 1 and (.[0]
        | type == "object"
        and ((if has("_default") then ._default else 20 end) | type == "number" and . >= 0)
        and ([to_entries[] | select(.key != "_default") | .value
              | type == "number" and . >= 0] | all)
        )
    ' "$WEIGHTS_FILE" >/dev/null; then
        printf "ERROR: invalid weights file '%s'; weights must be non-negative numbers\n" "$WEIGHTS_FILE" >&2
        exit 1
    fi

    default_weight="$(jq -r 'if has("_default") then ._default else 20 end' "$WEIGHTS_FILE")"
    weighted_tests=""
    for name in "${test_names[@]}"; do
        weight="$(jq -r --arg name "$name" '.[$name] // empty' "$WEIGHTS_FILE")"
        if [[ -z "$weight" ]]; then
            weight="$default_weight"
        fi
        weighted_tests+="$weight $name"$'\n'
    done
    weighted_tests="$(printf '%s' "$weighted_tests" | LC_ALL=C sort -k1,1 -rg -k2,2)"

    printf 'Using weighted bin packing (weights from %s)\n' "$WEIGHTS_FILE" >&2
else
    default_weight=20
    weighted_tests=""
    for name in "${test_names[@]}"; do
        weighted_tests+="$default_weight $name"$'\n'
    done
    weighted_tests="${weighted_tests%$'\n'}"

    echo "Warning: weights file not found or jq not available, using equal weights" >&2
fi

# Assign each test to the shard with the smallest accumulated weight.
shard_count="$PARTITIONS"
test_count="${#test_names[@]}"
if [[ ${#PARTITIONS} -gt ${#test_count} || (${#PARTITIONS} -eq ${#test_count} && "$PARTITIONS" > "$test_count") ]]; then
    shard_count="${#test_names[@]}"
fi
shard_assignments="$(awk -v partitions="$shard_count" '
BEGIN {
    for (i = 0; i < partitions; i++) {
        shard_weight[i] = 0
    }
}
{
    weight = $1
    name = $2
    min_shard = 0
    min_weight = shard_weight[0]
    for (i = 1; i < partitions; i++) {
        if (shard_weight[i] < min_weight) {
            min_weight = shard_weight[i]
            min_shard = i
        }
    }
    shard_weight[min_shard] += weight
    print min_shard, weight, name
}
END {
    for (i = 0; i < partitions; i++) {
        printf "Shard %d estimated weight: %ds\n", i, shard_weight[i] > "/dev/stderr"
    }
}' <<< "$weighted_tests")"

printf "Total tests matching '%s': %d, Partitions: %s\n" "$TEST_PATTERN" "${#test_names[@]}" "$PARTITIONS" >&2

matrix_json='{"include":['
first_shard=true
for (( shard = 0; shard < shard_count; shard++ )); do
    shard_tests="$(awk -v shard="$shard" '$1 == shard { print $3 }' <<< "$shard_assignments" | tr "\n" "|" | sed "s/|$//")"
    if [[ -z "$shard_tests" ]]; then
        continue
    fi

    if [[ "$first_shard" == "false" ]]; then
        matrix_json+=","
    fi
    first_shard=false

    test_count="$(tr "|" "\n" <<< "$shard_tests" | awk 'END { print NR }')"
    matrix_json+="{\"id\":$shard,\"description\":\"shard-$shard ($test_count tests)\",\"test_pattern\":\"$shard_tests\"}"
    printf 'Shard %d: %d tests: %s\n' "$shard" "$test_count" "$shard_tests" >&2
done

matrix_json+=']}'
printf '%s\n' "$matrix_json"
