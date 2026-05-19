#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Walk every internal/test/integration/docker-compose-multiexec*.yml and
# print "<image>=<dockerfile>" lines for services that have BOTH a literal
# dockerfile path (no ${...} placeholders) AND a hatest-* image tag.
#
# Output is sorted and deduplicated by image tag. Used by the VM-integration
# CI prep job to drive parallel `docker build` and produce
# docker-images.tar.

set -euo pipefail

SEARCH_DIR="${1:-internal/test/integration}"

shopt -s nullglob
compose_files=("${SEARCH_DIR}"/docker-compose-multiexec*.yml)
if [ ${#compose_files[@]} -eq 0 ]; then
    echo "discover-vm-docker-images.sh: no docker-compose-multiexec*.yml under ${SEARCH_DIR}" >&2
    exit 1
fi

awk '
    /^  [a-zA-Z]/ {
        if (df && img && !(img in seen)) { seen[img]=1; print img "=" df }
        df=""; img=""
    }
    /dockerfile:/ {
        sub(/.*dockerfile: */, ""); gsub(/["'"'"']/, ""); sub(/^\.\/*/, "")
        if ($0 !~ /\$\{/) df=$0
    }
    /image: *hatest-/ { sub(/.*image: */, ""); img=$0 }
    END { if (df && img && !(img in seen)) print img "=" df }
' "${compose_files[@]}" | sort
