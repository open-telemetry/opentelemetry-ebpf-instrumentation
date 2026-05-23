#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Roll up daily CI snapshots into a weekly report.
# Downloads snapshot artifacts from recent runs of the daily workflow,
# then runs the weekly subcommand to merge and re-aggregate them.
#
# Environment variables (all have defaults suitable for GitHub Actions):
#   GH_TOKEN          - Auth token for gh CLI (set from github.token in the workflow)
#   GITHUB_REPOSITORY - owner/repo string (auto-set by GitHub Actions)
#   WORKFLOW_FILE     - Filename of the daily workflow (default: daily_test_analysis.yml)
#   LOOKBACK_RUNS     - How many recent daily runs to pull artifacts from (default: 15)
#   SINCE             - YYYY-MM-DD; only include runs on or after this date (default: 7 days ago)
#   SNAPSHOT_OUT      - Optional path to write a JSON snapshot for a future monthly rollup
#   SCRIPT_DIR        - Override for the directory containing this script

set -euo pipefail

WORKFLOW_FILE="${WORKFLOW_FILE:-daily_test_analysis.yml}"
LOOKBACK_RUNS="${LOOKBACK_RUNS:-15}"
# GitHub caps per_page at 100; reject anything outside [1, 100] to fail fast
# instead of producing a confusing gh api error.
if ! [[ "$LOOKBACK_RUNS" =~ ^[0-9]+$ ]] || [ "$LOOKBACK_RUNS" -lt 1 ] || [ "$LOOKBACK_RUNS" -gt 100 ]; then
  echo "Error: LOOKBACK_RUNS must be an integer between 1 and 100, got: $LOOKBACK_RUNS" >&2
  exit 1
fi
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

SNAPSHOTS_DIR="$WORK_DIR/snapshots"
mkdir -p "$SNAPSHOTS_DIR"

echo "Listing recent runs of ${WORKFLOW_FILE}..." >&2
RUN_IDS=$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/${WORKFLOW_FILE}/runs?status=success&per_page=${LOOKBACK_RUNS}" \
  --jq '.workflow_runs[].id')

if [ -z "$RUN_IDS" ]; then
  echo "Warning: no successful daily runs found" >&2
fi

for RUN_ID in $RUN_IDS; do
  echo "  Downloading snapshot from run ${RUN_ID}..." >&2
  if ! gh run download "$RUN_ID" --repo "$GITHUB_REPOSITORY" \
    --pattern "ci-daily-snapshot-*" \
    -D "$SNAPSHOTS_DIR/$RUN_ID" 2>/dev/null; then
    echo "    (no snapshot artifact, skipping)" >&2
  fi
done

SNAPSHOT_COUNT=$(find "$SNAPSHOTS_DIR" -name "*.json" -type f | wc -l | tr -d ' ')
echo "Found $SNAPSHOT_COUNT snapshot file(s)" >&2

echo "Generating weekly report..." >&2
EXTRA_ARGS=()
if [ -n "${SINCE:-}" ]; then
  EXTRA_ARGS+=(--since="$SINCE")
fi
if [ -n "${SNAPSHOT_OUT:-}" ]; then
  EXTRA_ARGS+=(--snapshot-out="$SNAPSHOT_OUT")
fi
go run "${SCRIPT_DIR}/" weekly \
  --snapshots-dir="$SNAPSHOTS_DIR" \
  --repo="$GITHUB_REPOSITORY" \
  "${EXTRA_ARGS[@]}"
