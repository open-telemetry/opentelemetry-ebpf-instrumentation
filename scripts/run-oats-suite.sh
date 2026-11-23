#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

suite=${1:?usage: run-oats-suite.sh <suite>}
if [[ ! "$suite" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]; then
  echo "Invalid OATS suite name: $suite" >&2
  exit 1
fi

root=$(git rev-parse --show-toplevel)
suite_dir="$root/internal/test/oats/$suite"
if [[ ! -f "$suite_dir/oats-config.yaml" ]]; then
  echo "No OATS v3 config for suite $suite" >&2
  exit 1
fi

cases=()
if [[ -n "${OATS_CASES:-}" ]]; then
  read -r -a cases <<< "$OATS_CASES"
  for case_name in "${cases[@]}"; do
    if [[ ! "$case_name" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]; then
      echo "Invalid OATS case basename: $case_name" >&2
      exit 1
    fi
  done
fi

cd "$suite_dir"
OATS_ARTIFACT_DIR="$suite_dir/build" \
  "$root/scripts/run-oats-with-log.sh" build/oats.log "$root/.tools/oats/oats" \
  run --config oats-config.yaml --container-runtime docker --gcx "$root/.tools/oats/gcx" \
  --timeout "${TESTCASE_TIMEOUT:-5m}" --absent-timeout 10s --no-cache -vvv "${cases[@]}"
