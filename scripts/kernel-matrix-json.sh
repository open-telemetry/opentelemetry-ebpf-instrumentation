#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Usage: kernel-matrix-json.sh --kind=<integration|verifier> [--all] [--yaml=<path>]
#
# Emits a GitHub Actions JSON matrix of kernels with the requested
# pr_<kind> flag set to true in kernels.yaml. --all bypasses the flag and
# emits every kernel in the file.
set -euo pipefail

KIND=integration
ALL=false
YAML="${OBI_KERNELS_YAML:-internal/test/vm/kernels.yaml}"

for arg in "$@"; do
    case "$arg" in
        --kind=*) KIND="${arg#--kind=}" ;;
        --all)    ALL=true ;;
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

if [ "$ALL" = "true" ]; then
    FILTER='true'
else
    case "$KIND" in
        integration) FILTER='.pr_integration == true' ;;
        verifier)    FILTER='.pr_verifier == true' ;;
        *) echo "unknown kind: $KIND" >&2; exit 1 ;;
    esac
fi

yq -o=json -I=0 "
  {\"include\": [
    .kernels[] | select(${FILTER}) | {
      \"id\":      .id,
      \"lvh_tag\": .lvh_tag
    }
  ]}
" "$YAML"
