#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# CI Supervisor: evaluate failed workflow runs and rerun flaky failures.
# Called by .github/workflows/supervisor_rerun-flaky.yml
#
# Required environment variables:
#   GH_TOKEN       - GitHub token with actions:write
#   RUN_ID         - The workflow run ID that failed
#   WORKFLOW_NAME  - The name of the failed workflow
#   REPO           - The owner/repo string (e.g. open-telemetry/opentelemetry-ebpf-instrumentation)

set -euo pipefail

MAX_ATTEMPTS=2

echo "Evaluating run ${RUN_ID} -- workflow: ${WORKFLOW_NAME}"

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

# --- Scan this workflow's failed jobs ---
FOUND_FAILURE=0

while IFS=$'\t' read -r job_name job_conclusion; do
  FOUND_FAILURE=1
  # Unrecoverable: lint/format/tidy failures won't be fixed by re-running
  if [ "$WORKFLOW_NAME" = "Pull request checks" ] \
     && echo "$job_name" | grep -qi "lint"; then
    if [ "$VERDICT" != "skip" ]; then
      VERDICT="skip"
      REASON="Lint job failed in '${WORKFLOW_NAME}' -- static analysis/style failure, re-run will not help"
    fi
  fi
done < <(echo "$RUN_JSON" | jq -r '.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out") | [.name, .conclusion] | @tsv')

if [ "$FOUND_FAILURE" -eq 0 ]; then
  echo "No failed or timed-out jobs found. Exiting."
  exit 0
fi

# --- Take action ---
if [ "$VERDICT" = "rerun" ]; then
  echo "Re-running failed jobs for run ${RUN_ID}..."
  gh run rerun "$RUN_ID" --repo "$REPO" --failed
else
  echo "Skipping re-run: ${REASON}"
fi
