#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

log_file=$1
shift
mkdir -p "$(dirname -- "$log_file")"
"$@" 2>&1 | tee "$log_file"
