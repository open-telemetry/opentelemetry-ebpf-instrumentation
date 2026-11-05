#!/usr/bin/env bash
set -euo pipefail

# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

if command -v sha256sum >/dev/null 2>&1; then
  hash=$(printf '%s' "${MISE_ENABLE_TOOLS:-}" | sha256sum | cut -d ' ' -f 1)
else
  hash=$(printf '%s' "${MISE_ENABLE_TOOLS:-}" | shasum -a 256 | cut -d ' ' -f 1)
fi

echo "hash=$hash" >> "$GITHUB_OUTPUT"
