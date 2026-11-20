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
# Bound untrusted API input to the maximum portable signed 32-bit integer.
MAX_PORTABLE_SIGNED_INT=2147483647

echo "Evaluating run ${RUN_ID} -- workflow: ${WORKFLOW_NAME}"

# --- Get run details ---
RUN_JSON=$(gh run view "$RUN_ID" --repo "$REPO" --json attempt,jobs,name)
if ! PARSED_RUN=$(jq -Rser --argjson max_portable_int "$MAX_PORTABLE_SIGNED_INT" '
  . as $run_json
  # Validate the token before fromjson rounds it on jq 1.6.
  | ($run_json
    | capture("^\\s*\\{\\s*\"attempt\"\\s*:\\s*[1-9][0-9]*([eE][+]?[0-9]+)?\\s*,"))
  | ($run_json | fromjson)
  | if ((.attempt | type) == "number"
        and .attempt >= 1
        and .attempt <= $max_portable_int
        and (.attempt | floor) == .attempt
        and (.name | type) == "string"
        and (.jobs | type) == "array"
        and all(.jobs[];
          (.name | type) == "string"
          and (.conclusion | type) == "string"
          and (.conclusion != "cancelled"
            or ((.databaseId | type) == "number"
              and .databaseId >= 1
              and (.databaseId | floor) == .databaseId))))
      then
        (.attempt | floor | tostring),
        (.jobs[]
          | select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "cancelled")
          | [.name, .conclusion, (.databaseId // 0 | tostring)]
          | @tsv)
      else
        error("invalid run response")
      end
' <<<"$RUN_JSON"); then
  echo "Invalid GitHub run response." >&2
  exit 1
fi

# A job stopped by its timeout-minutes concludes as cancelled, like one cancelled by a user or a newer run
job_timed_out() {
  gh api "repos/${REPO}/check-runs/$1/annotations" --jq '.[].message' \
    | grep -q "exceeded the maximum execution time"
}

RUN_DETAILS=()
while IFS= read -r line; do
  RUN_DETAILS+=("$line")
done <<<"$PARSED_RUN"
ATTEMPT=${RUN_DETAILS[0]}
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

for ((index = 1; index < ${#RUN_DETAILS[@]}; index++)); do
  IFS=$'\t' read -r job_name conclusion job_id <<<"${RUN_DETAILS[$index]}"
  if [ "$conclusion" = "cancelled" ] && ! job_timed_out "$job_id"; then
    continue
  fi
  FOUND_FAILURE=1
  # Unrecoverable: lint/clang-format/clang-tidy failures are deterministic
  # and won't be fixed by re-running. The Lint workflow is dedicated to
  # these so any failure under it is unrecoverable. PR checks hosts the
  # clang-format/clang-tidy jobs so match those by job name there.
  if [ "$WORKFLOW_NAME" = "Lint" ] \
     || { [ "$WORKFLOW_NAME" = "PR checks" ] \
          && echo "$job_name" | grep -qiE "lint|clang"; }; then
    if [ "$VERDICT" != "skip" ]; then
      VERDICT="skip"
      REASON="Lint/format job failed in '${WORKFLOW_NAME}' -- static analysis/style failure, re-run will not help"
    fi
  fi
done

if [ "$FOUND_FAILURE" -eq 0 ]; then
  echo "No failed or timed-out jobs found. Exiting."
  exit 0
fi

# --- Take action ---
if [ "$VERDICT" = "rerun" ]; then
  RUN_CONTEXT=$(gh api "repos/${REPO}/actions/runs/${RUN_ID}")
  if ! RUN_REF=$(jq -ser '
    if length == 1
      and (.[0].event | type) == "string"
      and (.[0].head_sha | type) == "string"
      and (.[0].head_sha | test("^[0-9a-fA-F]{40}$"))
      and (.[0].head_repository.full_name | type) == "string"
      and (.[0].head_repository.full_name | test("^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$"))
      and (.[0].head_repository.full_name | split("/")[1] | . != "." and . != "..")
      and (.[0].head_branch | type) == "string"
      and (.[0].head_branch | length) > 0
      and (.[0].head_branch | explode | all(. > 32 and . != 127))
    then .[0] | [.event, .head_sha, .head_repository.full_name, .head_branch] | @tsv
    else error("invalid run ref")
    end
  ' <<<"$RUN_CONTEXT"); then
    echo "Invalid GitHub run ref response." >&2
    exit 1
  fi
  IFS=$'\t' read -r RUN_EVENT RUN_SHA HEAD_REPO HEAD_BRANCH <<<"$RUN_REF"
  if [ "$RUN_EVENT" = "pull_request" ] || [ "$RUN_EVENT" = "push" ]; then
    if ! git check-ref-format "refs/heads/${HEAD_BRANCH}"; then
      echo "Invalid GitHub head branch." >&2
      exit 1
    fi
    HEAD_BRANCH_URI=$(jq -rn --arg branch "$HEAD_BRANCH" '$branch | @uri')
    HEAD_REF=$(gh api "repos/${HEAD_REPO}/git/ref/heads/${HEAD_BRANCH_URI}")
    if ! CURRENT_SHA=$(jq -ser '
      if length == 1 and .[0].object.type == "commit"
        and (.[0].object.sha | type) == "string"
        and (.[0].object.sha | test("^[0-9a-fA-F]{40}$"))
      then .[0].object.sha
      else error("invalid head ref")
      end
    ' <<<"$HEAD_REF"); then
      echo "Invalid GitHub head ref response." >&2
      exit 1
    fi
    if [ "$RUN_SHA" != "$CURRENT_SHA" ]; then
      echo "Skipping re-run: run ${RUN_ID} is no longer the head of ${HEAD_REPO}:${HEAD_BRANCH}"
      exit 0
    fi
  fi
  echo "Re-running failed jobs for run ${RUN_ID}..."
  gh run rerun "$RUN_ID" --repo "$REPO" --failed
else
  echo "Skipping re-run: ${REASON}"
fi
