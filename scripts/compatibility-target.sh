#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

: "${TARGET_REF:?TARGET_REF is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

sha=$(git rev-parse --verify --end-of-options "${TARGET_REF}^{commit}")
printf 'sha=%s\n' "$sha" >> "$GITHUB_OUTPUT"
