#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

INSTALL_DIR=${1:-.tools/oats}
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
x86_64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*)
  echo "unsupported architecture: $ARCH" >&2
  exit 1
  ;;
esac
if [[ "$OS" != linux ]]; then
  echo "OATS integration tests require Linux (got $OS)" >&2
  exit 1
fi

case "$ARCH" in
amd64)
  # renovate: datasource=github-release-attachments depName=oats-linux-amd64 packageName=grafana/oats versioning=semver
  OATS_VERSION=v0.11.0
  OATS_SHA256=35608cc075c3c9af15559c52652096272cf7a1aaf49c455a1646d825025e7e75
  # renovate: datasource=github-release-attachments depName=gcx-linux-amd64 packageName=grafana/gcx versioning=semver
  GCX_VERSION=v1.7.1
  GCX_SHA256=5f1601feac13d850017064a9b556f11983de6def2986ba0bee402a947659c3e9
  ;;
arm64)
  # renovate: datasource=github-release-attachments depName=oats-linux-arm64 packageName=grafana/oats versioning=semver
  OATS_VERSION=v0.11.0
  OATS_SHA256=35b63d3b53291dc8f05f1f1981b01a5119d41d0820602a655100881ac72e05eb
  # renovate: datasource=github-release-attachments depName=gcx-linux-arm64 packageName=grafana/gcx versioning=semver
  GCX_VERSION=v1.7.1
  GCX_SHA256=1d8284557e66dd5c6e4d5b37a651afca98bea42729df7b4aa8720464360b2f54
  ;;
esac

mkdir -p "$INSTALL_DIR"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

download_and_install() {
  local name=$1 version=$2 checksum=$3
  local archive="${name}_${version#v}_linux_${ARCH}.tar.gz"
  local url="https://github.com/grafana/${name}/releases/download/${version}/${archive}"
  curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors -o "$TMP_DIR/$archive" "$url"
  printf '%s  %s\n' "$checksum" "$TMP_DIR/$archive" | sha256sum --check --status
  tar -xzf "$TMP_DIR/$archive" -C "$TMP_DIR" "$name"
  install -m 0755 "$TMP_DIR/$name" "$INSTALL_DIR/$name"
}

download_and_install oats "$OATS_VERSION" "$OATS_SHA256"
download_and_install gcx "$GCX_VERSION" "$GCX_SHA256"
