#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Build the "<image>=<dockerfile>[;<ARG>=<value>...]" entries read from stdin
# (see discover-integration-images.sh --build-targets) and `docker save` them to OUTPUT_TAR.

set -euo pipefail

OUTPUT_TAR="${1:?usage: $0 OUTPUT_TAR < entries}"
# 4 keeps disk + buildkit pressure manageable on a 4-core runner.
PARALLEL="${PARALLEL:-4}"

build_image() {
    local entry="$1"
    local tag="${entry%%=*}"
    local spec="${entry#*=}"
    local dockerfile="${spec%%;*}"
    local pairs pair
    local args=()

    IFS=";" read -ra pairs <<< "${spec}"
    for pair in "${pairs[@]:1}"; do
        args+=(--build-arg "${pair}")
    done

    echo "Building ${tag} from ${dockerfile}..."
    docker build --quiet -t "${tag}" -f "${dockerfile}" --label "obi.test.build-spec=${spec}" "${args[@]}" .
}
export -f build_image

mapfile -t ENTRIES
echo "Building ${#ENTRIES[@]} Docker images into ${OUTPUT_TAR}"
if [ ${#ENTRIES[@]} -eq 0 ]; then
    exit 0
fi

# shellcheck disable=SC2016
printf '%s\n' "${ENTRIES[@]}" | xargs -P "${PARALLEL}" -I {} bash -c 'build_image "$1"' _ {}

docker save "${ENTRIES[@]%%=*}" -o "${OUTPUT_TAR}"
echo "Docker images saved ($(du -h "${OUTPUT_TAR}" | cut -f1))"
docker builder prune -af
