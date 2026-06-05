#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Pull a pre-built kernel image from cilium/little-vm-helper-images on quay.io
# and extract vmlinuz + modules into OUT_DIR.
#
# Usage: pull-kernel.sh <kernel_id> <arch>
#   kernel_id: entry id from kernels.yaml (must declare lvh_tag)
#   arch:      amd64 (arm64 also supported by LVH but not exercised by CI)
#
# Env (optional):
#   OBI_KERNELS_YAML  path to kernels.yaml (default: ../kernels.yaml relative to this script)
#   OUT_DIR           output directory (default: ./out)
#
# Every kernels.yaml entry MUST carry a `digest: "sha256:<64-hex>"` field;
# pulls are always content-addressed against quay.io to defend against an
# attacker re-pushing a dated LVH tag. Renovate keeps the digests fresh.
#
# Outputs in $OUT_DIR:
#   vmlinuz-${id}-${arch}                  (kernel image)
#   vmlinuz-${id}-${arch}.config           (kernel config)
#   vmlinuz-${id}-${arch}.buildinfo        (json metadata)
#   modules-${id}-${arch}/                 (lib/modules/<ver> tree)
set -euo pipefail

KERNEL_ID="${1:?usage: pull-kernel.sh <kernel_id> <arch>}"
ARCH="${2:?usage: pull-kernel.sh <kernel_id> <arch>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBI_KERNELS_YAML="${OBI_KERNELS_YAML:-${SCRIPT_DIR}/../kernels.yaml}"
OUT_DIR="${OUT_DIR:-${PWD}/out}"
LVH_REGISTRY="${LVH_REGISTRY:-quay.io/lvh-images/kernel-images}"

case "$ARCH" in
    amd64) DOCKER_PLATFORM=linux/amd64 ;;
    arm64) DOCKER_PLATFORM=linux/arm64 ;;
    *) echo "pull-kernel.sh: arch must be amd64 or arm64 (got '${ARCH}')" >&2; exit 1 ;;
esac

if ! command -v yq >/dev/null 2>&1; then
    echo "pull-kernel.sh: yq not installed (need https://github.com/mikefarah/yq)" >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "pull-kernel.sh: docker not installed" >&2
    exit 1
fi

LVH_TAG=$(yq ".kernels[] | select(.id == \"${KERNEL_ID}\") | .lvh_tag // \"\"" "$OBI_KERNELS_YAML")
LVH_DIGEST=$(yq ".kernels[] | select(.id == \"${KERNEL_ID}\") | .digest // \"\"" "$OBI_KERNELS_YAML")

if [ -z "$LVH_TAG" ] || [ "$LVH_TAG" = "null" ]; then
    echo "pull-kernel.sh: kernel id '${KERNEL_ID}' missing or has no lvh_tag in ${OBI_KERNELS_YAML}" >&2
    exit 1
fi

if [ -z "$LVH_DIGEST" ] || [ "$LVH_DIGEST" = "null" ]; then
    echo "pull-kernel.sh: kernel id '${KERNEL_ID}' has no digest in ${OBI_KERNELS_YAML} (every entry must pin sha256:<64-hex>)" >&2
    exit 1
fi
if ! [[ "$LVH_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "pull-kernel.sh: invalid digest format for kernel id '${KERNEL_ID}': '${LVH_DIGEST}' (want sha256:<64-hex>)" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"; docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

PULL_REF="${LVH_REGISTRY}@${LVH_DIGEST}"
IMAGE="${LVH_REGISTRY}:${LVH_TAG}@${LVH_DIGEST}"
echo "pull-kernel.sh: pulling ${PULL_REF} (${DOCKER_PLATFORM})" >&2
docker pull --quiet --platform "$DOCKER_PLATFORM" "$PULL_REF" >&2

CID="$(docker create --platform "$DOCKER_PLATFORM" "$PULL_REF")"
docker cp "${CID}:/data" "${WORKDIR}/" >&2

KVER_DIR="$(ls -d ${WORKDIR}/data/kernels/*/ | head -1)"
if [ -z "$KVER_DIR" ]; then
    echo "pull-kernel.sh: no kernel found in image" >&2
    exit 1
fi
KVER="$(basename "$KVER_DIR")"
VMLINUZ_SRC="$(ls ${KVER_DIR}boot/vmlinuz-* | head -1)"
CONFIG_SRC="$(ls ${KVER_DIR}boot/config-* | head -1)"
KREL="$(basename "$VMLINUZ_SRC" | sed 's/^vmlinuz-//')"
MODULES_SRC="${KVER_DIR}lib/modules/${KREL}"

ART_BASE="vmlinuz-${KERNEL_ID}-${ARCH}"
cp "$VMLINUZ_SRC" "${OUT_DIR}/${ART_BASE}"
cp "$CONFIG_SRC"  "${OUT_DIR}/${ART_BASE}.config"

MODULES_DST="${OUT_DIR}/modules-${KERNEL_ID}-${ARCH}"
# Flatten the /lib/modules/<release>/ tree directly into the destination so
# the in-VM mountpoint /lib/modules/$(uname -r) contains {kernel/, modules.dep,
# modules.alias.bin, ...} at its top level — what modprobe expects. Nesting
# the release as a subdir works on some kmod builds via fallback tree walk but
# breaks on stricter ones (busybox modprobe on alpine + LVH amd64 6.6).
rm -rf "$MODULES_DST"
mkdir -p "$MODULES_DST"
# mv contents (not the dir itself) so MODULES_DST stays as the top-level
# stage directory we just created.
mv "$MODULES_SRC"/* "$MODULES_DST"/
rmdir "$MODULES_SRC" 2>/dev/null || true

cat > "${OUT_DIR}/${ART_BASE}.buildinfo" <<EOF
{
  "kernel_id": "${KERNEL_ID}",
  "kernel_release": "${KREL}",
  "kernel_branch": "${KVER}",
  "source": "lvh",
  "lvh_tag": "${LVH_TAG}",
  "lvh_digest": "${LVH_DIGEST}",
  "lvh_image": "${IMAGE}",
  "target_arch": "${ARCH}",
  "pulled_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image_sha256": "$(sha256sum "${OUT_DIR}/${ART_BASE}" | awk '{print $1}')",
  "config_sha256": "$(sha256sum "${OUT_DIR}/${ART_BASE}.config" | awk '{print $1}')"
}
EOF

echo "pull-kernel.sh: done" >&2
echo "  ${OUT_DIR}/${ART_BASE}" >&2
echo "  ${OUT_DIR}/${ART_BASE}.config" >&2
echo "  ${OUT_DIR}/${ART_BASE}.buildinfo" >&2
echo "  ${OUT_DIR}/modules-${KERNEL_ID}-${ARCH}/" >&2
