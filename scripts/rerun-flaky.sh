#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# CI Supervisor: evaluate failed workflow runs and rerun flaky failures.
# Called by .github/workflows/supervisor_rerun-flaky.yml
#
# Required environment variables:
#   GH_TOKEN       - GitHub token with actions:write and pull-requests:write
#   RUN_ID         - The workflow run ID that failed
#   WORKFLOW_NAME  - The name of the failed workflow
#   REPO           - The owner/repo string (e.g. open-telemetry/opentelemetry-ebpf-instrumentation)

set -euo pipefail

MAX_ATTEMPTS=2

# --- Resolve the associated PR ---
RUN_DATA=$(gh api "repos/${REPO}/actions/runs/${RUN_ID}" \
  --jq '{pr: .pull_requests[0].number, sha: .head_sha}')
PR_NUMBER=$(echo "$RUN_DATA" | jq -r '.pr // empty')
HEAD_SHA=$(echo "$RUN_DATA" | jq -r '.sha // empty')

# Fallback for fork PRs: pull_requests array is often empty
if [ -z "$PR_NUMBER" ] && [ -n "$HEAD_SHA" ]; then
  echo "pull_requests empty — falling back to commits/${HEAD_SHA}/pulls lookup"
  PR_NUMBER=$(gh api "repos/${REPO}/commits/${HEAD_SHA}/pulls" \
    --jq '[.[] | select(.state == "open")] | .[0].number // empty' || true)
fi

if [ -z "$PR_NUMBER" ]; then
  echo "No PR associated with run ${RUN_ID}. Exiting."
  exit 0
fi
if ! echo "$PR_NUMBER" | grep -qE '^[0-9]+$'; then
  echo "Invalid PR number: ${PR_NUMBER}. Exiting."
  exit 1
fi
echo "PR #${PR_NUMBER} -- workflow: ${WORKFLOW_NAME}"

# --- Get run details ---
RUN_JSON=$(gh run view "$RUN_ID" --repo "$REPO" --json attempt,jobs,name)
ATTEMPT=$(echo "$RUN_JSON" | jq -r '.attempt')
echo "Current attempt: ${ATTEMPT}"

# --- Check attempt limit first ---
VERDICT="rerun"
REASON=""
if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
  VERDICT="skip"
  REASON="Maximum re-run attempts reached (attempt ${ATTEMPT} of ${MAX_ATTEMPTS})"
fi

# --- Build job summary table ---
JOBS_TABLE=""

while IFS=$'\t' read -r job_name job_conclusion job_started job_completed; do
  duration="unknown"
  if [ -n "$job_started" ] && [ -n "$job_completed" ] \
     && [ "$job_started" != "null" ] && [ "$job_completed" != "null" ]; then
    start_epoch=$(date -d "$job_started" +%s 2>/dev/null || echo "0")
    end_epoch=$(date -d "$job_completed" +%s 2>/dev/null || echo "0")
    if [ "$start_epoch" -gt 0 ] && [ "$end_epoch" -gt 0 ]; then
      duration_min=$(( (end_epoch - start_epoch) / 60 ))
      duration="${duration_min}m"
    fi
  fi

  job_verdict="flaky"

  # Unrecoverable: lint/format/tidy failures won't be fixed by re-running
  if [ "$WORKFLOW_NAME" = "Pull request checks" ] \
     && echo "$job_name" | grep -qi "lint"; then
    job_verdict="unrecoverable (lint failure)"
    if [ "$VERDICT" != "skip" ]; then
      VERDICT="skip"
      REASON="Lint job failed in '${WORKFLOW_NAME}' -- static analysis/style failure, re-run will not help"
    fi
  fi
  JOBS_TABLE="${JOBS_TABLE}| ${job_name} | ${job_conclusion} | ${duration} | ${job_verdict} |\n"
done < <(echo "$RUN_JSON" | jq -r '.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out") | [.name, .conclusion, .startedAt, .completedAt] | @tsv')

if [ -z "$JOBS_TABLE" ]; then
  echo "No failed or timed-out jobs found. Exiting."
  exit 0
fi

# --- Take action ---
if [ "$VERDICT" = "rerun" ]; then
  ACTION_LINE="Re-running failed jobs (attempt $((ATTEMPT + 1)) of ${MAX_ATTEMPTS})"
  echo "Re-running failed jobs for run ${RUN_ID}..."
  gh run rerun "$RUN_ID" --repo "$REPO" --failed
else
  ACTION_LINE="NOT re-running. Reason: ${REASON}"
  echo "Skipping re-run: ${REASON}"
fi

# --- Post PR comment ---
COMMENT_BODY="### CI Supervisor: ${WORKFLOW_NAME} (attempt ${ATTEMPT})

| Job | Conclusion | Duration | Verdict |
|-----|-----------|----------|---------|
$(printf '%b' "$JOBS_TABLE")
**Action**: ${ACTION_LINE}"

gh pr comment "$PR_NUMBER" --repo "$REPO" --body "$COMMENT_BODY"
echo "Posted audit comment on PR #${PR_NUMBER}"
