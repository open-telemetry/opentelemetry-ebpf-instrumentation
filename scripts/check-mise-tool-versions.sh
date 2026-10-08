#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# These stages contain tool/runtime versions that are also managed by mise.
# The image tags have different formats, so each mapping includes its tag regex.
docker_mise_tools=(
  'markdown|markdownlint-cli2|^davidanson/markdownlint-cli2:v([^@]+)'
  'gradle-java|gradle|^gradle:([^@-]+)'
  'python39|python|python([0-9]+\.[0-9]+)-'
  'python314|python|python([0-9]+\.[0-9]+)-'
  'golang|go|^golang:([^@]+)'
)

for mapping in "${docker_mise_tools[@]}"; do
  IFS='|' read -r stage tool image_regex <<< "$mapping"
  image=$(awk -v stage="$stage" '$1 == "FROM" && $NF == stage {print $2}' dependencies.Dockerfile)
  if [[ -z "$image" ]]; then
    echo "Unable to find $stage image in dependencies.Dockerfile" >&2
    exit 1
  fi
  if [[ ! "$image" =~ $image_regex ]]; then
    echo "Unable to extract $tool version from $stage image: $image" >&2
    exit 1
  fi
  docker_version=${BASH_REMATCH[1]}
  mise_versions=$(mise config get --file mise.toml "tools.$tool")
  # `mise config get` prints arrays in TOML-like form and scalar values plainly.
  mise_versions=$(printf '%s\n' "$mise_versions" | tr -d '[]",' | xargs)
  if ! [[ " $mise_versions " == *" $docker_version "* ]]; then
    echo "$tool versions differ: mise.toml=$mise_versions, dependencies.Dockerfile ($stage)=$docker_version" >&2
    exit 1
  fi
  echo "$tool version matches for $stage: $docker_version"
done

mise_version=$(mise config get --file mise.toml tools.golangci-lint)
go_mod_version=$(go mod edit -json internal/tools/go.mod \
  | jq -r '.Require[] | select(.Path == "github.com/golangci/golangci-lint/v2") | .Version')
go_mod_version=${go_mod_version#v}

if [[ "$mise_version" != "$go_mod_version" ]]; then
  echo "golangci-lint versions differ: mise.toml=$mise_version, internal/tools/go.mod=$go_mod_version" >&2
  exit 1
fi

echo "golangci-lint versions match: $mise_version"
