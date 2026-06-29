#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Collect CI test data from GitHub Actions for the main branch.
# Downloads gotestsum JSON reports and Docker log artifacts,
# parses them, and produces a Markdown report on stdout.
#
# Environment variables (all have defaults suitable for GitHub Actions):
#   GH_TOKEN          - Auth token for gh CLI (set from github.token in the workflow)
#   GITHUB_REPOSITORY - owner/repo string (auto-set by GitHub Actions)
#   LOOKBACK_DAYS     - Number of days to look back (default: 5, max limited by artifact retention)
#   SCRIPT_DIR        - Override for the directory containing this script
#   SNAPSHOT_OUT      - Optional path to write a JSON snapshot for the weekly rollup

set -euo pipefail

LOOKBACK_DAYS="${LOOKBACK_DAYS:-5}"
if ! [[ "$LOOKBACK_DAYS" =~ ^[0-9]+$ ]] || [ "$LOOKBACK_DAYS" -lt 1 ] || [ "$LOOKBACK_DAYS" -gt 5 ]; then
  echo "Error: LOOKBACK_DAYS must be an integer between 1 and 5, got: $LOOKBACK_DAYS" >&2
  exit 1
fi
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

REPORTS_DIR="$WORK_DIR/reports"
LOGS_DIR="$WORK_DIR/logs"
META_FILE="$WORK_DIR/meta.json"

mkdir -p "$REPORTS_DIR" "$LOGS_DIR"

# Compute the cutoff date
if date --version >/dev/null 2>&1; then
  SINCE=$(date -u -d "-${LOOKBACK_DAYS} days" +%Y-%m-%dT00:00:00Z)
else
  SINCE=$(date -u -v-"${LOOKBACK_DAYS}"d +%Y-%m-%dT00:00:00Z)
fi
echo "Collecting data since: $SINCE" >&2

# Workflows that produce gotestsum JSON artifacts
GOTESTSUM_WORKFLOWS=(
  "Integration tests"
  "Integration tests ARM"
  "Integration tests K8S"
  "Unit tests"
)

# Workflows tracked at job level only (no gotestsum JSON artifacts).
# OATS uses Ginkgo, so test-level parsing is not supported yet.
JOB_ONLY_WORKFLOWS=(
  "Integration tests VM"
  "OATS tests"
  "PR checks"
)

ALL_WORKFLOWS=("${GOTESTSUM_WORKFLOWS[@]}" "${JOB_ONLY_WORKFLOWS[@]}")

# Artifact name patterns by workflow.
report_pattern_for() {
  case "$1" in
    "Integration tests")     echo "integration-reports-*" ;;
    "Integration tests ARM") echo "integration-arm-reports-*" ;;
    "Integration tests K8S") echo "integration-k8s-reports-*" ;;
    "Unit tests")            echo "unit-reports-*" ;;
    *)                       echo "" ;;
  esac
}

logs_pattern_for() {
  case "$1" in
    "Integration tests")     echo "integration-logs-*" ;;
    "Integration tests ARM") echo "integration-arm-logs-*" ;;
    "Integration tests K8S") echo "integration-k8s-logs-*" ;;
    "Integration tests VM")  echo "vm-logs-*" ;;
    "OATS tests")            echo "oats-logs-*" ;;
    *)                       echo "" ;;
  esac
}

echo "[" > "$META_FILE"
FIRST_META=true

for WORKFLOW_NAME in "${ALL_WORKFLOWS[@]}"; do
  echo "Querying workflow: $WORKFLOW_NAME" >&2

  # Query completed and cancelled runs (timeouts surface as cancelled).
  # 100 runs per page is enough for a 5-day window per workflow.
  RUNS=""
  for STATUS in completed cancelled; do
    BATCH=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs?branch=main&event=push&status=${STATUS}&created=%3E%3D${SINCE}&per_page=100" \
      --jq ".workflow_runs[] | select(.name == \"${WORKFLOW_NAME}\") | {id: .id, name: .name, conclusion: .conclusion, created_at: .created_at, head_sha: .head_sha, run_attempt: .run_attempt}" \
      2>&1) || { echo "  API error ($STATUS): $BATCH" >&2; BATCH=""; }
    if [ -n "$BATCH" ]; then
      RUNS="${RUNS}${RUNS:+$'\n'}${BATCH}"
    fi
  done

  if [ -z "$RUNS" ]; then
    echo "  No runs found" >&2
    continue
  fi

  while IFS= read -r run_json; do
    [ -z "$run_json" ] && continue

    RUN_ID=$(echo "$run_json" | jq -r '.id')
    CONCLUSION=$(echo "$run_json" | jq -r '.conclusion')
    CREATED_AT=$(echo "$run_json" | jq -r '.created_at')
    SHA=$(echo "$run_json" | jq -r '.head_sha')

    echo "  Run $RUN_ID ($CONCLUSION) - $CREATED_AT" >&2

    if [ "$FIRST_META" = true ]; then
      FIRST_META=false
    else
      echo "," >> "$META_FILE"
    fi
    cat >> "$META_FILE" <<METAEOF
{"run_id":"${RUN_ID}","sha":"${SHA}","created_at":"${CREATED_AT}","workflow":"${WORKFLOW_NAME}","conclusion":"${CONCLUSION}"}
METAEOF

    RUN_REPORTS_DIR="$REPORTS_DIR/$RUN_ID"
    mkdir -p "$RUN_REPORTS_DIR"

    # Download gotestsum report artifacts (skip for job-only workflows)
    REPORT_PATTERN=$(report_pattern_for "$WORKFLOW_NAME")
    REPORT_COUNT=0
    if [ -n "$REPORT_PATTERN" ]; then
      gh run download "$RUN_ID" --repo "$GITHUB_REPOSITORY" \
        --pattern "$REPORT_PATTERN" \
        -D "$RUN_REPORTS_DIR" 2>/dev/null || true
      REPORT_COUNT=$(find "$RUN_REPORTS_DIR" -name "*.log" -type f 2>/dev/null | wc -l)
    fi

    echo "    Downloaded $REPORT_COUNT report files" >&2

    # For failed runs, also download Docker log artifacts
    LOGS_PATTERN=$(logs_pattern_for "$WORKFLOW_NAME")
    if [ -n "$LOGS_PATTERN" ] && { [ "$CONCLUSION" = "failure" ] || [ "$CONCLUSION" = "timed_out" ] || [ "$CONCLUSION" = "cancelled" ]; }; then
      RUN_LOGS_DIR="$LOGS_DIR/$RUN_ID"
      mkdir -p "$RUN_LOGS_DIR"
      gh run download "$RUN_ID" --repo "$GITHUB_REPOSITORY" \
        --pattern "$LOGS_PATTERN" \
        -D "$RUN_LOGS_DIR" 2>/dev/null || true
      LOG_COUNT=$(find "$RUN_LOGS_DIR" -name "*.log" -type f 2>/dev/null | wc -l)
      echo "    Downloaded $LOG_COUNT Docker log files" >&2
    fi

  done <<< "$RUNS"
done

echo "]" >> "$META_FILE"

echo "Generating report..." >&2
SNAPSHOT_ARGS=()
if [ -n "${SNAPSHOT_OUT:-}" ]; then
  SNAPSHOT_ARGS=(--snapshot-out="$SNAPSHOT_OUT")
fi
go run "${SCRIPT_DIR}/" daily \
  --reports-dir="$REPORTS_DIR" \
  --logs-dir="$LOGS_DIR" \
  --meta="$META_FILE" \
  --repo="$GITHUB_REPOSITORY" \
  "${SNAPSHOT_ARGS[@]}"
