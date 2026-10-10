#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Validate Mise task definitions without installing every tool in mise.toml.
# CI jobs install only the tools they use through MISE_ENABLE_TOOLS.
if [[ ! -f mise.lock ]]; then
  echo "mise.lock is missing; run 'mise lock'" >&2
  exit 1
fi
mise tasks validate

mise_version=$(mise config get --file mise.toml tools.golangci-lint)
go_mod_version=$(go mod edit -json internal/tools/go.mod \
  | jq -r '.Require[] | select(.Path == "github.com/golangci/golangci-lint/v2") | .Version')
go_mod_version=${go_mod_version#v}

if [[ "$mise_version" != "$go_mod_version" ]]; then
  echo "golangci-lint versions differ: mise.toml=$mise_version, internal/tools/go.mod=$go_mod_version" >&2
  exit 1
fi

echo "golangci-lint versions match: $mise_version"
