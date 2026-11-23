#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(git rev-parse --show-toplevel)
oci_bin=${OCI_BIN:-docker}
cd "$root"

if [[ ",${PREBUILT_IMAGES:-}," == *,hatest-obi,* ]]; then
  "$oci_bin" image inspect hatest-obi >/dev/null
else
  mise run generate
  "$oci_bin" build -t hatest-obi -f internal/test/integration/components/obi/Dockerfile .
fi

./scripts/install-oats-tools.sh "$root/.tools/oats"
go build -o "$root/.tools/oats/weaver-finalizer" ./internal/test/oats/finalizer
mkdir -p "${TEST_OUTPUT:-$root/testoutput}/run"
