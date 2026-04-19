#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"

find_apache_bin() {
  if command -v httpd >/dev/null 2>&1; then
    printf '%s\n' "$(command -v httpd)"
    return 0
  fi

  printf 'could not find `httpd`; install Apache HTTP Server and ensure `httpd` is on PATH\n' >&2
  return 1
}

start_instance() {
  local apache_bin="$1"
  local name="$2"
  local config_path="$EXAMPLE_DIR/standalone/$name/httpd.conf"
  local log_dir="$EXAMPLE_DIR/standalone/$name/logs"

  mkdir -p "$log_dir"
  "$apache_bin" -C "Define EXAMPLE_ROOT $EXAMPLE_DIR" -k start -f "$config_path"
}

main() {
  local apache_bin

  apache_bin="$(find_apache_bin)"

  start_instance "$apache_bin" edge
  start_instance "$apache_bin" recommendations-v1
  start_instance "$apache_bin" recommendations-v2
}

main "$@"
