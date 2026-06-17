#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Enumerate integration-test Docker images (sorted, deduplicated, side-effect free):
#   --build-targets  (default) "<image>=<dockerfile>" build pairs from docker-compose-multiexec*.yml.
#   --base-images    base images from registries in PREPULL_REGISTRY_RE, to pre-pull (see pull-base-images.sh).

set -euo pipefail

SEARCH_DIR="${SEARCH_DIR:-internal/test/integration}"
MODE="${1:---build-targets}"

# Registries that rate-limit anonymous pulls with no auth escape hatch. Docker Hub
# is excluded (the test jobs authenticate to it). Extend if another registry 429s.
PREPULL_REGISTRY_RE="${PREPULL_REGISTRY_RE:-mcr\.microsoft\.com}"

case "${MODE}" in
--build-targets)
    shopt -s nullglob
    compose_files=("${SEARCH_DIR}"/docker-compose-multiexec*.yml)
    if [ ${#compose_files[@]} -eq 0 ]; then
        echo "discover-integration-images.sh: no docker-compose-multiexec*.yml under ${SEARCH_DIR}" >&2
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
    ;;
--base-images)
    find "${SEARCH_DIR}" -type f -name 'Dockerfile*' -print0 \
        | xargs -0 grep -hE "^FROM[[:space:]]+(${PREPULL_REGISTRY_RE})/" \
        | awk '{print $2}' \
        | sort -u
    ;;
*)
    echo "usage: $0 [--build-targets|--base-images]" >&2
    exit 1
    ;;
esac
