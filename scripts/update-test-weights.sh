#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Regenerate integration-test-weights.generated.json from the gotestsum JSON
# reports uploaded by the "Integration tests" workflow.
#
# Usage:
#   ./scripts/update-test-weights.sh [reports-directory]
#
# With a directory, every *.log under it whose path contains "-$ARCH-" is read.
# Without one, the integration-reports artifacts of the last $RUNS successful
# push runs on main are downloaded with the gh CLI.
#
# Environment:
#   ARCH  - architecture whose reports are used (default: amd64)
#   RUNS  - number of main runs to download (default: 10)
#   GITHUB_REPOSITORY - owner/repo to download from (default: the gh default repo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEIGHTS_FILE="$SCRIPT_DIR/integration-test-weights.generated.json"
DEFAULT_WEIGHT=20
ARCH="${ARCH:-amd64}"
RUNS="${RUNS:-10}"

for command_name in jq find; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Error: missing required command: $command_name" >&2
        exit 1
    fi
done

if [ $# -ge 1 ]; then
    REPORTS_DIR="$1"
    if [ ! -d "$REPORTS_DIR" ]; then
        echo "Error: '$REPORTS_DIR' is not a directory" >&2
        exit 1
    fi
else
    if ! command -v gh >/dev/null 2>&1; then
        echo "Error: gh is required when no reports directory is given" >&2
        exit 1
    fi
    if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
        echo "Error: RUNS must be a positive integer, got '$RUNS'" >&2
        exit 1
    fi
    REPORTS_DIR="$(mktemp -d)"
    trap 'rm -rf "$REPORTS_DIR"' EXIT
    repo_args=()
    if [ -n "${GITHUB_REPOSITORY:-}" ]; then
        repo_args=(--repo "$GITHUB_REPOSITORY")
    fi
    run_ids="$(gh run list "${repo_args[@]}" \
        --workflow pull_request_integration_tests.yml \
        --branch main --event push --status success \
        --limit "$RUNS" --json databaseId --jq '.[].databaseId')"
    if [ -z "$run_ids" ]; then
        echo "Error: no successful main runs found" >&2
        exit 1
    fi
    for run_id in $run_ids; do
        gh run download "$run_id" "${repo_args[@]}" \
            --pattern "integration-reports-*-$ARCH-*" \
            --dir "$REPORTS_DIR/$run_id" >&2 \
            || echo "Warning: no reports downloaded for run $run_id" >&2
    done
fi

mapfile -t report_files < <(find "$REPORTS_DIR" -type f -name '*.log' -path "*-$ARCH-*")
if [ "${#report_files[@]}" -eq 0 ]; then
    echo "Error: no reports matching '*-$ARCH-*/*.log' found in '$REPORTS_DIR'" >&2
    exit 1
fi

WEIGHTS="$(
    cat "${report_files[@]}" \
    | jq -R -c 'fromjson? | select(
          .Action == "pass"
          and ((.Package // "") | endswith("internal/test/integration"))
          and ((.Test // "") | test("^Test[^/]*$"))
        ) | {name: .Test, elapsed: .Elapsed}' \
    | jq -s --argjson default "$DEFAULT_WEIGHT" '
        group_by(.name)
        | map({
            key: .[0].name,
            value: (map(.elapsed) | sort
                    | if length % 2 == 1 then .[(length - 1) / 2]
                      else (.[length / 2 - 1] + .[length / 2]) / 2 end
                    | round)
          })
        | {_default: $default} + from_entries'
)"

TOTAL="$(jq 'length - 1' <<< "$WEIGHTS")"
if [ "$TOTAL" -eq 0 ]; then
    echo "Error: no passing top-level integration tests found in ${#report_files[@]} reports" >&2
    exit 1
fi

jq --indent 2 . <<< "$WEIGHTS" > "$WEIGHTS_FILE"
echo "Updated $WEIGHTS_FILE with $TOTAL tests from ${#report_files[@]} reports" >&2
