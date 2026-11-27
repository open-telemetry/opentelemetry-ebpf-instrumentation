#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Boot the AL2023 kernel and signed livepatch that duplicate inet_csk_listen_stop.
set -euo pipefail
cd "$(dirname "$0")/../../.."

release=6.12.113-138.209.amzn2023.x86_64
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
guest="$workdir/initramfs"
mkdir -p "$guest"/{bin,dev,proc,sys}

extract_rpm() {
    local package=$1 checksum=$2 member=$3
    local rpm="$workdir/$package"
    curl --fail --silent --show-error --location --retry 3 \
        "https://cdn.amazonlinux.com/al2023/blobstore/$checksum/$package" -o "$rpm"
    printf '%s  %s\n' "$checksum" "$rpm" | sha256sum --check >&2
    bsdtar -xOf "$rpm" "$member"
}

extract_rpm "kernel6.12-$release.rpm" \
    eef3a6aed3a0d0b889d1b33303086803fc52a9e7f18e2009a11894883a3d2154 \
    "./lib/modules/$release/vmlinuz" > "$workdir/vmlinuz"
extract_rpm kernel-livepatch-6.12.113-138.209-1.0-1.amzn2023.x86_64.rpm \
    26f5cd52258479b67267195c405c68ab706f4cd4b0c56cb5b650d51c905dc87f \
    "./var/lib/kpatch/$release/livepatch-inet-reject.ko" > "$guest/livepatch-inet-reject.ko"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags=privileged_tests,livepatch_vm \
    -o "$guest/kprobe.test" ./pkg/internal/ebpf/kprobe
cp "$(command -v busybox)" "$guest/bin/busybox"
cat > "$guest/init" <<'INIT'
#!/bin/busybox sh
set -eu
/bin/busybox mount -t devtmpfs devtmpfs /dev
trap 'echo "$?" > /dev/ttyS1; /bin/busybox poweroff -f' EXIT
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t tracefs tracefs /sys/kernel/tracing
test_name=TestAL2023Livepatch
pattern="^$test_name$"
[ "$(/kprobe.test -test.list "$pattern")" = "$test_name" ]
/kprobe.test -test.run "$pattern" -test.v -test.timeout=2m
INIT
chmod +x "$guest/init"
bsdtar --format=newc -czf "$workdir/initramfs.gz" -C "$guest" .

accel=(-accel tcg -cpu max)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    accel=(-accel kvm -cpu host)
fi
timeout 5m qemu-system-x86_64 "${accel[@]}" -m 768M -smp 2 \
    -kernel "$workdir/vmlinuz" -initrd "$workdir/initramfs.gz" \
    -append 'console=ttyS0 quiet panic=-1 rdinit=/init' -no-reboot -nic none \
    -display none -monitor none -serial stdio -serial "file:$workdir/result"

result=$(tr -d '\r' < "$workdir/result")
if [[ "$result" != 0 ]]; then
    echo "Livepatch VM test exit status: ${result:-missing}" >&2
    exit 1
fi
