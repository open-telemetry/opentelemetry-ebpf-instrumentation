#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Run the BPF verifier test suite against an Amazon Linux 2023 kernel.
#
# AL2023 ships without CONFIG_NET_9P, so the standard launchvm 9p-virtfs
# path doesn't apply. This script self-contains the entire flow:
#   1. Extract vmlinuz + modules from AL2023 kernel RPM (Dockerfile here).
#   2. Cross-compile verifier.test on the host (BPF .o files are
#      go:embed'd via bpf2go, so the binary is fully self-contained).
#   3. Pack a minimal initramfs (static busybox + verifier.test + tiny
#      init that mounts /proc /sys /sys/fs/bpf, runs the binary, prints
#      OBI-VERIFIER-RESULT: <exit> on the serial console, powers off).
#   4. Boot the kernel with qemu, parse the result line.
#
# Usage: run.sh <kernel_nvr> [kernel_pkg]
# Example: run.sh 6.1.172-216.329.amzn2023
#          run.sh 6.12.88-119.157.amzn2023 kernel6.12
set -euo pipefail

KERNEL_NVR="${1:?usage: run.sh <kernel_nvr> [kernel_pkg]}"
KERNEL_PKG="${2:-kernel}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../../.." && pwd)"
BUSYBOX_IMAGE="$(awk '$1=="FROM" && $4=="busybox-musl" {print $2}' "${REPO_ROOT}/dependencies.Dockerfile")"
if [ -z "${BUSYBOX_IMAGE}" ]; then
    echo "Unable to find busybox-musl image in dependencies.Dockerfile" >&2
    exit 1
fi
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# 1. Build the kernel-extract image and copy out vmlinuz + initramfs.
KSTAGE="${WORKDIR}/kstage"
mkdir -p "${KSTAGE}"
echo "run.sh: extracting AL2023 kernel ${KERNEL_NVR} (${KERNEL_PKG})" >&2
docker buildx build \
    --platform linux/amd64 \
    --build-arg "KERNEL_NVR=${KERNEL_NVR}" \
    --build-arg "KERNEL_PKG=${KERNEL_PKG}" \
    --output "type=local,dest=${KSTAGE}" \
    "${SCRIPT_DIR}" >&2

KVER_DIR="$(ls -d ${KSTAGE}/data/kernels/*/ | head -1)"
KREL="$(basename "$KVER_DIR")"
VMLINUZ="${KVER_DIR}boot/vmlinuz-${KREL}"

# 2. Cross-compile the verifier test binary (self-contained, no /obi needed).
TEST_BIN="${WORKDIR}/verifier.test"
echo "run.sh: compiling verifier.test" >&2
(cd "${REPO_ROOT}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go test -c -tags=bpf_verifier_tests \
        -o "${TEST_BIN}" \
        ./pkg/internal/ebpf/verifier/)

# 3. Stage the initramfs.
IRD="${WORKDIR}/initramfs"
mkdir -p "${IRD}"/{bin,proc,sys,dev}
mkdir -p "${IRD}/sys/fs/bpf" "${IRD}/sys/kernel/debug" "${IRD}/sys/kernel/tracing"

# Static (musl) busybox so it runs without any libc.
docker run --rm --platform linux/amd64 -v "${IRD}/bin":/out \
    "${BUSYBOX_IMAGE}" sh -c 'cp /bin/busybox /out/busybox' >&2

cp "${TEST_BIN}" "${IRD}/verifier.test"
chmod +x "${IRD}/verifier.test"

cat > "${IRD}/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t bpf bpf /sys/fs/bpf
/bin/busybox mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
/bin/busybox mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null
ulimit -l unlimited 2>/dev/null
echo "OBI-VERIFIER-BEGIN"
/verifier.test -test.timeout=20m -test.parallel=8
RESULT=$?
/bin/busybox sync
printf '%s\n' "${RESULT}" > /dev/ttyS1 2>/dev/null
# Halt deterministically; /init returning would cause kernel panic.
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null
echo o > /proc/sysrq-trigger 2>/dev/null
/bin/busybox poweroff -f 2>/dev/null
while :; do /bin/busybox sleep 1; done
INIT
chmod +x "${IRD}/init"

IRD_IMG="${WORKDIR}/initramfs.cpio.gz"
(cd "${IRD}" && find . | cpio -o -H newc 2>/dev/null | gzip -1) > "${IRD_IMG}"

# 4. Boot.
if [ -e /dev/kvm ]; then
    ACCEL="-enable-kvm -cpu host"
else
    ACCEL="-accel tcg,thread=multi -cpu Skylake-Client"  # x86-64-v2 for AL2023 glibc
fi
QEMU_LOG="${WORKDIR}/qemu.log"
RESULT_FILE="${WORKDIR}/obi-result"
rm -f "${RESULT_FILE}"
echo "run.sh: launching qemu" >&2
# ttyS0: console + kernel printk + test stdout.
# ttyS1: dedicated result channel — only init writes to it, never the kernel.
timeout 1500 qemu-system-x86_64 ${ACCEL} -m 4G -smp 2 \
    -kernel "${VMLINUZ}" \
    -initrd "${IRD_IMG}" \
    -append "earlyprintk=ttyS0 console=ttyS0 loglevel=0 quiet panic=3 rdinit=/init" \
    -serial mon:stdio \
    -serial "file:${RESULT_FILE}" \
    -no-reboot -nographic 2>&1 | tee "${QEMU_LOG}"

RESULT="$(tr -d '\r\n\t ' < "${RESULT_FILE}" 2>/dev/null)"
if [ -z "$RESULT" ] || ! printf '%s' "$RESULT" | grep -qE '^[0-9]+$'; then
    echo "run.sh: no valid result in ${RESULT_FILE} (got: '$(cat "${RESULT_FILE}" 2>/dev/null)')" >&2
    exit 1
fi
echo "run.sh: result=${RESULT}" >&2
exit "${RESULT}"
