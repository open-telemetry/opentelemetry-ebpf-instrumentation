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
if ! PARSED_RUN=$(jq -ser --argjson max_portable_int "$MAX_PORTABLE_SIGNED_INT" '
  if length != 1 then
    error("expected one run response")
  else
    .[0]
    | if ((.attempt | type) == "number"
        and (.attempt | tostring | test("^[1-9][0-9]*([eE][+]?[0-9]+)?$"))
        and .attempt >= 1
        and .attempt <= $max_portable_int
        and (.attempt | floor) == .attempt
        and (.name | type) == "string"
        and (.jobs | type) == "array"
        and all(.jobs[];
          (.name | type) == "string"
          and (.conclusion | type) == "string"))
      then
        (.attempt | floor | tostring),
        (.jobs[]
          | select(.conclusion == "failure" or .conclusion == "timed_out")
          | [.name, .conclusion]
          | @tsv)
      else
        error("invalid run response")
      end
  end
' <<<"$RUN_JSON"); then
  echo "Invalid GitHub run response." >&2
  exit 1
fi

mapfile -t RUN_DETAILS <<<"$PARSED_RUN"
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
  IFS=$'\t' read -r job_name _ <<<"${RUN_DETAILS[$index]}"
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
  echo "Re-running failed jobs for run ${RUN_ID}..."
  gh run rerun "$RUN_ID" --repo "$REPO" --failed
else
  echo "Skipping re-run: ${REASON}"
fi
