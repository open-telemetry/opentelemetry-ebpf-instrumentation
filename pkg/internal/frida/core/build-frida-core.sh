#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

readonly version=17.24.3
work_dir=""

usage() {
    printf 'Usage: %s OUTPUT_DIRECTORY [amd64|arm64]\n' "${0##*/}"
    printf 'Build a Frida Core shared library from a checksum-pinned official devkit.\n'
    printf 'CC selects one compiler executable; use a target compiler for cross-linking.\n'
}

cleanup() {
    if [[ -n "$work_dir" && -d "$work_dir" ]]; then
        rm -rf -- "$work_dir"
    fi
}
trap cleanup EXIT
trap 'printf "Frida packaging failed at line %s\n" "$LINENO" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

main() {
    if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
        usage
        return
    fi
    if [[ $# -lt 1 || $# -gt 2 || "$1" == -* ]]; then
        usage >&2
        return 1
    fi
    local output_dir="$1" architecture="${2:-$(uname -m)}" target checksum
    case "$architecture" in
        amd64|x86_64)
            target=x86_64
            checksum=9a11abf474899a33af6dd9af8a064448b23947a29a3af747eb3c7851591ffec2
            ;;
        arm64|aarch64)
            target=arm64
            checksum=925bda0e1628b7b282dda370e293ab84aedaacfc11d259378ee6a0885a9b99f7
            ;;
        *) printf 'Unsupported architecture: %s\n' "$architecture" >&2; return 1 ;;
    esac
    local compiler="${CC:-cc}" dependency
    for dependency in curl sha256sum tar mktemp readelf "$compiler"; do
        command -v "$dependency" >/dev/null || { printf 'Missing command: %s\n' "$dependency" >&2; return 1; }
    done
    mkdir -p -- "$output_dir"
    output_dir="$(cd -- "$output_dir" && pwd -P)"
    work_dir="$(mktemp -d "$output_dir/.frida-build.XXXXXXXX")"
    local archive="frida-core-devkit-${version}-linux-${target}.tar.xz"
    local url="https://github.com/frida/frida/releases/download/${version}/${archive}"
    printf 'Downloading %s\n' "$url" >&2
    curl --fail --location --silent --show-error --retry 3 "$url" -o "$work_dir/devkit.tar.xz"
    printf '%s  %s\n' "$checksum" "$work_dir/devkit.tar.xz" | sha256sum --check --status
    tar -xJf "$work_dir/devkit.tar.xz" -C "$work_dir" --no-same-owner \
        ./libfrida-core.a ./frida-core.h ./frida-core-example.c
    "$compiler" -shared -Wl,--build-id=sha1 -Wl,-soname,libfrida-core.so \
        -Wl,-z,noexecstack -Wl,-z,relro,-z,now \
        -o "$work_dir/libfrida-core.so" \
        -Wl,--whole-archive "$work_dir/libfrida-core.a" -Wl,--no-whole-archive \
        -lm -ldl -latomic -lrt -lresolv -pthread
    {
        printf 'Frida: %s\nTarget: linux-%s\nSource: %s\nSource SHA256: %s\n' "$version" "$target" "$url" "$checksum"
        "$compiler" --version
        readelf -d "$work_dir/libfrida-core.so"
        readelf --version-info "$work_dir/libfrida-core.so"
    } > "$work_dir/build-manifest.txt"
    (cd -- "$work_dir" && sha256sum libfrida-core.so) > "$work_dir/SHA256SUMS"
    mv -- "$work_dir/libfrida-core.so" "$output_dir/libfrida-core.so"
    mv -- "$work_dir/build-manifest.txt" "$output_dir/build-manifest.txt"
    mv -- "$work_dir/SHA256SUMS" "$output_dir/SHA256SUMS"
    printf 'Built %s/libfrida-core.so\n' "$output_dir" >&2
}

main "$@"
