#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Usage: kernel-matrix-json.sh --kind=<integration|verifier> [--all] [--arch=<amd64|arm64>] [--yaml=<path>]
#
# Emits a GitHub Actions JSON matrix of kernels from kernels.yaml.
#
#   --kind=integration|verifier
#       Keep entries whose pr_<kind> flag is true. Ignored with --all.
#   --all
#       Bypass the pr_* flag and emit every kernel in the file (still
#       filtered by --arch if set).
#   --arch=amd64|arm64
#       Keep only entries whose `arch` list contains this value. Entries
#       with no `arch` field are treated as [amd64]. When set, the value
#       is also copied onto each matrix row as `arch` so the workflow can
#       pass it to prepare-kernel.sh / docker pull --platform.
#       When omitted, output matches the historical shape (no arch field)
#       and is not filtered by architecture — existing amd64 workflows
#       keep working unchanged.
set -euo pipefail

KIND=integration
ALL=false
ARCH=
YAML="${OBI_KERNELS_YAML:-internal/test/vm/kernels.yaml}"

for arg in "$@"; do
    case "$arg" in
        --kind=*) KIND="${arg#--kind=}" ;;
        --all)    ALL=true ;;
        --arch=*) ARCH="${arg#--arch=}" ;;
        --yaml=*) YAML="${arg#--yaml=}" ;;
        *) echo "unknown arg: $arg" >&2; exit 1 ;;
    esac
done

if ! command -v yq >/dev/null 2>&1; then
    echo "kernel-matrix-json.sh: yq not installed" >&2
    exit 1
fi
if [ ! -f "$YAML" ]; then
    echo "kernel-matrix-json.sh: $YAML not found" >&2
    exit 1
fi

case "$ARCH" in
    ""|amd64|arm64) ;;
    *) echo "kernel-matrix-json.sh: --arch must be amd64 or arm64 (got '${ARCH}')" >&2; exit 1 ;;
esac

if [ "$ALL" = "true" ]; then
    KIND_FILTER='true'
else
    case "$KIND" in
        integration) KIND_FILTER='.pr_integration == true' ;;
        verifier)    KIND_FILTER='.pr_verifier == true' ;;
        *) echo "unknown kind: $KIND" >&2; exit 1 ;;
    esac
fi

# Missing `arch` means amd64-only
if [ -n "$ARCH" ]; then
    yq -o=json -I=0 "
      {\"include\": [
        .kernels[]
        | select(${KIND_FILTER})
        | select((.arch // [\"amd64\"]) | contains([\"${ARCH}\"]))
        | {
            \"id\":          .id,
            \"lvh_tag\":     .lvh_tag,
            \"arch\":        \"${ARCH}\",
            \"cgroup_mode\": (.cgroup_mode // \"hybrid\")
          }
      ]}
    " "$YAML"
else
    yq -o=json -I=0 "
      {\"include\": [
        .kernels[] | select(${KIND_FILTER}) | {
          \"id\":          .id,
          \"lvh_tag\":     .lvh_tag,
          \"cgroup_mode\": (.cgroup_mode // \"hybrid\")
        }
      ]}
    " "$YAML"
fi
