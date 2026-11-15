#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
suite_dir=$(basename -- "$PWD")
if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
  echo "COMPOSE_PROJECT_NAME is required when finalizing an OATS Compose fixture" >&2
  exit 1
fi
project_name=$COMPOSE_PROJECT_NAME
artifact_root=${OATS_ARTIFACT_DIR:-"$PWD/build"}
artifact_dir="$artifact_root/$project_name"
mkdir -p "$artifact_dir"

helper="$repo_root/.tools/oats/weaver-finalizer"
if [[ ! -x "$helper" ]]; then
  echo "Weaver finalizer helper is not built: $helper (run make oats-prereq)" >"$artifact_dir/weaver-validation.log"
  helper_status=1
else
  helper_status=0
  "$helper" -admin-url "${OATS_WEAVER_ADMIN_URL:-http://127.0.0.1:4320}" \
    -artifact-dir "$artifact_dir" -name "$suite_dir" >"$artifact_dir/weaver-validation.log" 2>&1 || helper_status=$?
fi

compose_status=0
docker compose logs --no-color >"$artifact_dir/compose.log" 2>&1 || compose_status=$?
if ((compose_status != 0)); then
  echo "failed to collect OATS Compose logs for $project_name; see $artifact_dir/compose.log" >&2
fi

if ((helper_status != 0)); then
  echo "Weaver finalization failed (exit $helper_status); see $artifact_dir/weaver-validation.log" >&2
  tail -n 40 "$artifact_dir/weaver-validation.log" >&2 || true
  exit "$helper_status"
fi

exit "$compose_status"
