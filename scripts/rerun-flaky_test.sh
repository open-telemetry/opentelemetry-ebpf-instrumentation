#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SCRIPT_UNDER_TEST="${SCRIPT_DIR}/rerun-flaky.sh"
TEST_DIR=$(mktemp -d)
FAKE_BIN="${TEST_DIR}/bin"
GH_LOG="${TEST_DIR}/gh.log"
GH_FIXTURE="${TEST_DIR}/run.json"

cleanup() {
  rm -rf -- "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p -- "$FAKE_BIN"
cat >"${FAKE_BIN}/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

{
  printf 'gh'
  printf ' %q' "$@"
  printf '\n'
} >>"$GH_LOG"

case "${1:-} ${2:-}" in
  "run view")
    expected=(run view "$RUN_ID" --repo "$REPO" --json attempt,jobs,name)
    action=view
    ;;
  "run rerun")
    expected=(run rerun "$RUN_ID" --repo "$REPO" --failed)
    action=rerun
    ;;
  *)
    printf 'Unexpected gh arguments: %s\n' "$*" >&2
    exit 90
    ;;
esac

actual=("$@")
if (( $# != ${#expected[@]} )); then
  printf 'Unexpected gh arguments: %s\n' "$*" >&2
  exit 90
fi
for ((index = 0; index < ${#expected[@]}; index++)); do
  if [[ "${actual[$index]}" != "${expected[$index]}" ]]; then
    printf 'Unexpected gh arguments: %s\n' "$*" >&2
    exit 90
  fi
done

case "$action" in
  view)
    if (( GH_VIEW_STATUS != 0 )); then
      exit "$GH_VIEW_STATUS"
    fi
    cat -- "$GH_FIXTURE"
    ;;
  rerun)
    exit "$GH_RERUN_STATUS"
    ;;
esac
EOF
chmod +x "${FAKE_BIN}/gh"

fail() {
  printf 'FAIL: %s: %s\n' "$1" "$2" >&2
  exit 1
}

run_case() {
  local name="$1"
  local workflow="$2"
  local fixture="$3"
  local expected_status="$4"
  local expected_calls="$5"
  local expected_output="$6"
  local view_status="${7:-0}"
  local rerun_status="${8:-0}"
  local output=""
  local status=0
  local calls=""

  printf '%s\n' "$fixture" >"$GH_FIXTURE"
  : >"$GH_LOG"

  set +e
  output=$(env \
    PATH="${FAKE_BIN}:${PATH}" \
    GH_LOG="$GH_LOG" \
    GH_FIXTURE="$GH_FIXTURE" \
    GH_VIEW_STATUS="$view_status" \
    GH_RERUN_STATUS="$rerun_status" \
    GH_TOKEN=test-token \
    RUN_ID=12345 \
    WORKFLOW_NAME="$workflow" \
    REPO=open-telemetry/obi \
    bash "$SCRIPT_UNDER_TEST" 2>&1)
  status=$?
  set -e

  calls=$(<"$GH_LOG")
  [[ "$calls" == "$expected_calls" ]] || \
    fail "$name" "unexpected gh calls: ${calls}"
  [[ "$calls" != *" cancel "* ]] || \
    fail "$name" "unexpected cancellation: ${calls}"
  if (( status != expected_status )); then
    fail "$name" "expected status ${expected_status}, got ${status}: ${output}"
  fi
  if [[ -n "$expected_output" && "$output" != *"$expected_output"* ]]; then
    fail "$name" "missing output '${expected_output}': ${output}"
  fi

  printf 'PASS: %s\n' "$name"
}

assert_rejected_call_is_logged() {
  local expected='gh run cancel 12345 --repo open-telemetry/obi'
  local status=0
  local calls=""

  : >"$GH_LOG"
  set +e
  env \
    PATH="${FAKE_BIN}:${PATH}" \
    GH_LOG="$GH_LOG" \
    RUN_ID=12345 \
    REPO=open-telemetry/obi \
    gh run cancel 12345 --repo open-telemetry/obi >/dev/null 2>&1
  status=$?
  set -e

  calls=$(<"$GH_LOG")
  (( status == 90 )) || fail "fake cancel audit" "expected status 90, got ${status}"
  [[ "$calls" == "$expected" ]] || \
    fail "fake cancel audit" "rejected call was not logged exactly: ${calls}"

  printf 'PASS: fake cancel audit\n'
}

view_call='gh run view 12345 --repo open-telemetry/obi --json attempt\,jobs\,name'
rerun_call="${view_call}"$'\n''gh run rerun 12345 --repo open-telemetry/obi --failed'

run_case "clean success" "Unit tests" \
  '{"attempt":1,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"success"}]}' \
  0 "$view_call" "No failed or timed-out jobs found"
run_case "ordinary failure" "Unit tests" \
  '{"attempt":1,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  0 "$rerun_call" "Re-running failed jobs"
run_case "timeout" "Integration tests" \
  '{"attempt":1,"name":"Integration tests","jobs":[{"name":"integration","conclusion":"timed_out"}]}' \
  0 "$rerun_call" "Re-running failed jobs"
run_case "mixed outcomes" "Integration tests" \
  '{"attempt":1,"name":"Integration tests","jobs":[{"name":"setup","conclusion":"success"},{"name":"test","conclusion":"failure"},{"name":"cleanup","conclusion":"cancelled"}]}' \
  0 "$rerun_call" "Re-running failed jobs"
run_case "lint workflow failure" "Lint" \
  '{"attempt":1,"name":"Lint","jobs":[{"name":"licenses","conclusion":"failure"}]}' \
  0 "$view_call" "Skipping re-run"
run_case "PR clang failure" "PR checks" \
  '{"attempt":1,"name":"PR checks","jobs":[{"name":"clang-format","conclusion":"failure"},{"name":"build","conclusion":"failure"}]}' \
  0 "$view_call" "Skipping re-run"
run_case "PR lint failure" "PR checks" \
  '{"attempt":1,"name":"PR checks","jobs":[{"name":"golangci-lint","conclusion":"failure"}]}' \
  0 "$view_call" "Skipping re-run"
run_case "PR ordinary failure" "PR checks" \
  '{"attempt":1,"name":"PR checks","jobs":[{"name":"build","conclusion":"failure"}]}' \
  0 "$rerun_call" "Re-running failed jobs"
run_case "second retry" "Unit tests" \
  '{"attempt":2,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  0 "$rerun_call" "Re-running failed jobs"
run_case "retry cap" "Unit tests" \
  '{"attempt":3,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  0 "$view_call" "Maximum re-run attempts reached"
run_case "irrelevant conclusions" "Unit tests" \
  '{"attempt":1,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"cancelled"},{"name":"queued","conclusion":"skipped"}]}' \
  0 "$view_call" "No failed or timed-out jobs found"
run_case "multiple run documents" "Unit tests" \
  $'{"attempt":1,"name":"Unit tests","jobs":[]}\n{"attempt":1,"name":"Unit tests","jobs":[]}' \
  1 "$view_call" "Invalid GitHub run response"
run_case "exponential attempt" "Unit tests" \
  '{"attempt":1e100,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  1 "$view_call" "Invalid GitHub run response"
run_case "bounded exponential attempt" "Unit tests" \
  '{"attempt":1e3,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  0 "$view_call" "Maximum re-run attempts reached"
run_case "fractional attempt rounded by jq" "Unit tests" \
  '{"attempt":1.0000000000000001,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  1 "$view_call" "Invalid GitHub run response"
run_case "malformed JSON" "Unit tests" '{"attempt":' \
  1 "$view_call" ""
run_case "malformed jobs" "Unit tests" \
  '{"attempt":1,"name":"Unit tests","jobs":null}' \
  1 "$view_call" ""
run_case "malformed job" "Unit tests" \
  '{"attempt":1,"name":"Unit tests","jobs":[{"name":"unit","conclusion":null}]}' \
  1 "$view_call" ""
run_case "malformed workflow name" "Unit tests" \
  '{"attempt":1,"name":null,"jobs":[{"name":"unit","conclusion":"failure"}]}' \
  1 "$view_call" ""
run_case "missing attempt" "Unit tests" \
  '{"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  1 "$view_call" ""
run_case "view API failure" "Unit tests" '{}' \
  22 "$view_call" "" 22
run_case "rerun API failure" "Unit tests" \
  '{"attempt":1,"name":"Unit tests","jobs":[{"name":"unit","conclusion":"failure"}]}' \
  23 "$rerun_call" "Re-running failed jobs" 0 23
assert_rejected_call_is_logged
