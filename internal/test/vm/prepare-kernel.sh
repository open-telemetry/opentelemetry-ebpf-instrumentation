#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Resolve a kernel entry from kernels.yaml to the on-disk paths the
# launchvm Makefile target consumes. Pulls from cilium/little-vm-helper-images
# on cache miss.
#
# Usage: prepare-kernel.sh <kernel_id> <arch>
#
# Prints two shell assignment lines on stdout, suitable for `eval`:
#   KERNEL=<path-to-vmlinuz>
#   MODULES_DIR=<path-to-modules-tree>
#
# All diagnostic output goes to stderr.

set -euo pipefail

KERNEL_ID="${1:?usage: prepare-kernel.sh <kernel_id> <arch>}"
ARCH="${2:?usage: prepare-kernel.sh <kernel_id> <arch>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNELS_YAML="${SCRIPT_DIR}/kernels.yaml"

if ! command -v yq >/dev/null 2>&1; then
    echo "prepare-kernel.sh: yq not installed (need https://github.com/mikefarah/yq)" >&2
    exit 1
fi

FOUND=$(yq ".kernels[] | select(.id == \"${KERNEL_ID}\") | .id" "$KERNELS_YAML")
if [ -z "$FOUND" ]; then
    echo "prepare-kernel.sh: kernel id '${KERNEL_ID}' not found in ${KERNELS_YAML}" >&2
    exit 1
fi

OUT_DIR="${SCRIPT_DIR}/lvh/out"
KERNEL_PATH="${OUT_DIR}/vmlinuz-${KERNEL_ID}-${ARCH}"
MODULES_PATH="${OUT_DIR}/modules-${KERNEL_ID}-${ARCH}"
if [ ! -f "$KERNEL_PATH" ] || [ ! -d "$MODULES_PATH" ]; then
    echo "prepare-kernel.sh: pulling lvh kernel ${KERNEL_ID} ${ARCH}" >&2
    OUT_DIR="$OUT_DIR" bash "${SCRIPT_DIR}/lvh/pull-kernel.sh" "$KERNEL_ID" "$ARCH" >&2
else
    echo "prepare-kernel.sh: lvh kernel cached at ${KERNEL_PATH}" >&2
fi
printf 'KERNEL=%s\nMODULES_DIR=%s\n' "$KERNEL_PATH" "$MODULES_PATH"
