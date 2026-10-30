#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Enumerate integration-test Docker images (sorted, deduplicated, side-effect free):
#   --build-targets  (default) "<image>=<dockerfile>[;<ARG>=<value>...]" build entries for the VM test
#                    subset: services of BUILD_COMPOSE_FILES plus the Go Auto SDK fixtures of go_auto_sdk_test.go.
#   --base-images    base images from registries in PREPULL_REGISTRY_RE, to pre-pull (see pull-base-images.sh).

set -euo pipefail

SEARCH_DIR="${SEARCH_DIR:-internal/test/integration}"
MODE="${1:---build-targets}"

BUILD_COMPOSE_FILES=(
    docker-compose-multiexec.yml
    docker-compose-multiexec-host.yml
    docker-compose-log-enricher.yml
    docker-compose-large-http-req.yml
    docker-compose-cp-enrollment.yml
)

# Registries that rate-limit anonymous pulls with no auth escape hatch. Docker Hub
# is excluded (the test jobs authenticate to it). Extend if another registry 429s.
PREPULL_REGISTRY_RE="${PREPULL_REGISTRY_RE:-mcr\.microsoft\.com}"

compose_build_targets() {
    local compose_files=()
    local file
    for file in "${BUILD_COMPOSE_FILES[@]}"; do
        if [ ! -f "${SEARCH_DIR}/${file}" ]; then
            echo "discover-integration-images.sh: ${SEARCH_DIR}/${file} not found" >&2
            exit 1
        fi
        compose_files+=("${SEARCH_DIR}/${file}")
    done

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
    ' "${compose_files[@]}"
}

go_auto_sdk_build_targets() {
    local dir="${SEARCH_DIR}/components/goautosdk"
    local otel_version toolchain mode sources

    echo "hatest-goautosdk-133=${dir}/Dockerfile-1.33"
    echo "hatest-goautosdk-latest=${dir}/Dockerfile-latest"

    for otel_version in 1.35.0 latest; do
        for toolchain in previous current; do
            for mode in embedded-only external-embedded embedded-external; do
                sources="main.go external.go"
                if [ "${mode}" = "embedded-only" ]; then
                    sources="main.go"
                fi
                echo "hatest-goautosdk-${otel_version//./-}-${toolchain}-${mode}=${dir}/Dockerfile-embedded;GO_TOOLCHAIN=${toolchain};OTEL_VERSION=${otel_version};SOURCES=${sources}"
            done
        done
    done
}

case "${MODE}" in
--build-targets)
    { compose_build_targets; go_auto_sdk_build_targets; } | sort
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
