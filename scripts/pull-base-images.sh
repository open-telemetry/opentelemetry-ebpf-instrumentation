#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Pull the rate-limited base images reported by discover-integration-images.sh
# (retrying on transient 429s) and optionally `docker save` them to OUTPUT_TAR.

set -euo pipefail

OUTPUT_TAR="${1:-}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-5}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mapfile -t IMAGES < <(bash "${SCRIPT_DIR}/discover-integration-images.sh" --base-images)

if [ ${#IMAGES[@]} -eq 0 ]; then
    echo "pull-base-images.sh: no base images found" >&2
    exit 1
fi

echo "Pulling ${#IMAGES[@]} base image(s):"
printf '  %s\n' "${IMAGES[@]}"

for image in "${IMAGES[@]}"; do
    attempt=1
    delay=5
    until docker pull --quiet "${image}"; do
        if [ "${attempt}" -ge "${MAX_ATTEMPTS}" ]; then
            echo "Failed to pull ${image} after ${MAX_ATTEMPTS} attempts" >&2
            exit 1
        fi
        echo "Pull of ${image} failed (attempt ${attempt}/${MAX_ATTEMPTS}); retrying in ${delay}s..." >&2
        sleep "${delay}"
        attempt=$((attempt + 1))
        delay=$((delay * 2))
    done
done

if [ -n "${OUTPUT_TAR}" ]; then
    mkdir -p "$(dirname "${OUTPUT_TAR}")"
    docker save "${IMAGES[@]}" -o "${OUTPUT_TAR}"
    echo "Saved ${#IMAGES[@]} image(s) to ${OUTPUT_TAR} ($(du -h "${OUTPUT_TAR}" | cut -f1))"
fi
