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
MARKER="<!-- ci-supervisor -->"

# --- Resolve the associated PR ---
RUN_DATA=$(gh api "repos/${REPO}/actions/runs/${RUN_ID}" \
  --jq '{pr: .pull_requests[0].number, head_branch: .head_branch, head_owner: .head_repository.owner.login}')
PR_NUMBER=$(echo "$RUN_DATA" | jq -r '.pr // empty')

# Fallback for fork PRs: pull_requests array is often empty.
# The commits/{sha}/pulls endpoint doesn't work for fork commits (the SHA
# doesn't exist in the base repo). Instead, query by head={owner}:{branch}.
if [ -z "$PR_NUMBER" ]; then
  HEAD_BRANCH=$(echo "$RUN_DATA" | jq -r '.head_branch // empty')
  HEAD_OWNER=$(echo "$RUN_DATA" | jq -r '.head_owner // empty')
  if [ -n "$HEAD_OWNER" ] && [ -n "$HEAD_BRANCH" ]; then
    echo "pull_requests empty — falling back to pulls?head=${HEAD_OWNER}:${HEAD_BRANCH} lookup"
    PR_NUMBER=$(gh api "repos/${REPO}/pulls?state=open&head=${HEAD_OWNER}:${HEAD_BRANCH}&per_page=1" \
      --jq '.[0].number // empty' || true)
  fi
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

# --- Build new table rows for this workflow's failed jobs ---
NEW_ROWS=""

while IFS=$'\t' read -r job_name job_conclusion; do
  # Unrecoverable: lint/format/tidy failures won't be fixed by re-running
  if [ "$WORKFLOW_NAME" = "Pull request checks" ] \
     && echo "$job_name" | grep -qi "lint"; then
    if [ "$VERDICT" != "skip" ]; then
      VERDICT="skip"
      REASON="Lint job failed in '${WORKFLOW_NAME}' -- static analysis/style failure, re-run will not help"
    fi
  fi

  if [ "$VERDICT" = "rerun" ]; then
    rerunning="Yes"
  else
    rerunning="No"
  fi

  NEW_ROWS="${NEW_ROWS}| ${WORKFLOW_NAME} | ${job_name} | ${job_conclusion} | ${rerunning} | ${ATTEMPT}/${MAX_ATTEMPTS} |
"
done < <(echo "$RUN_JSON" | jq -r '.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out") | [.name, .conclusion] | @tsv')

if [ -z "$NEW_ROWS" ]; then
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

# --- Fetch existing sticky comment (if any) and merge rows ---
EXISTING_COMMENT=$(gh api --paginate "repos/${REPO}/issues/${PR_NUMBER}/comments?per_page=100" 2>/dev/null \
  | jq -s --arg marker "$MARKER" '[.[][] | select(.body | startswith($marker))] | last | {id, body}' \
  || echo '{}')
EXISTING_COMMENT_ID=$(echo "$EXISTING_COMMENT" | jq -r '.id // empty')
EXISTING_BODY=$(echo "$EXISTING_COMMENT" | jq -r '.body // empty')

# Extract existing table rows, dropping rows that belong to the current workflow
# (they'll be replaced by NEW_ROWS).
KEPT_ROWS=""
if [ -n "$EXISTING_BODY" ]; then
  KEPT_ROWS=$(echo "$EXISTING_BODY" | grep '^|' | grep -v '^| Workflow' | grep -v '^|---' | grep -v "^| ${WORKFLOW_NAME} |" || true)
  if [ -n "$KEPT_ROWS" ]; then
    KEPT_ROWS="${KEPT_ROWS}
"
  fi
fi

# --- Build the full comment ---
COMMENT_BODY="${MARKER}
### CI Supervisor

| Workflow | Job | Last state | Re-running? | Attempt |
|----------|-----|-----------|-------------|---------|
${KEPT_ROWS}${NEW_ROWS}"

if [ -n "$EXISTING_COMMENT_ID" ]; then
  gh api "repos/${REPO}/issues/comments/${EXISTING_COMMENT_ID}" \
    --method PATCH --field body="$COMMENT_BODY" > /dev/null
  echo "Updated CI Supervisor comment (id: ${EXISTING_COMMENT_ID}) on PR #${PR_NUMBER}"
else
  gh pr comment "$PR_NUMBER" --repo "$REPO" --body "$COMMENT_BODY"
  echo "Posted CI Supervisor comment on PR #${PR_NUMBER}"
fi
