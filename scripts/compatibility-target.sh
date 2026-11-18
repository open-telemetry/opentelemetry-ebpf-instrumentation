#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

: "${BASE_REF:?BASE_REF is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

sha=$(git rev-parse --verify --end-of-options "${BASE_REF}^{commit}")
printf 'sha=%s\n' "$sha" >> "$GITHUB_OUTPUT"
