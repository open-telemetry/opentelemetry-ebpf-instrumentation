#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly COLLECTOR_BINARY="$SCRIPT_DIR/otelcol-dev/otelcol-dev"
readonly CONFIG_PATH="$SCRIPT_DIR/smoke-config.yaml"
readonly SMOKE_PORT="18080"
readonly SMOKE_URL="http://127.0.0.1:${SMOKE_PORT}/"
readonly TRACE_ATTEMPTS="60"

TMP_DIR=""
COLLECTOR_LOG=""
SERVER_LOG=""
COLLECTOR_PID=""
SERVER_PID=""

log_info() {
    printf 'INFO: %s\n' "$*" >&2
}

log_error() {
    printf 'ERROR: %s\n' "$*" >&2
}

on_error() {
    local -r line="$1"
    log_error "command failed at line $line"
}

process_is_running() {
    local -r pid="$1"
    kill -0 "$pid" 2>/dev/null
}

stop_process() {
    local -r pid="$1"
    local watchdog_pid=""

    if process_is_running "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        (
            sleep 10
            kill -KILL "$pid" 2>/dev/null || true
        ) &
        watchdog_pid="$!"
    fi

    wait "$pid" 2>/dev/null || true

    if [[ -n "$watchdog_pid" ]]; then
        kill -TERM "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
    fi
}

print_failure_logs() {
    if [[ -f "$COLLECTOR_LOG" ]]; then
        log_error "collector output:"
        tail -n 200 -- "$COLLECTOR_LOG" >&2
    fi
    if [[ -f "$SERVER_LOG" ]]; then
        log_error "HTTP server output:"
        tail -n 50 -- "$SERVER_LOG" >&2
    fi
}

cleanup() {
    local -r status="$?"
    trap - ERR EXIT INT TERM

    if [[ -n "$COLLECTOR_PID" ]]; then
        stop_process "$COLLECTOR_PID"
    fi
    if [[ -n "$SERVER_PID" ]]; then
        stop_process "$SERVER_PID"
    fi
    if (( status != 0 )); then
        print_failure_logs
    fi
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
}

check_dependencies() {
    local -a required=(curl grep mktemp python3 tail)
    local -a missing=()
    local command=""

    for command in "${required[@]}"; do
        if ! command -v "$command" >/dev/null 2>&1; then
            missing+=("$command")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "missing required commands: ${missing[*]}"
        return 1
    fi
}

check_inputs() {
    if (( EUID != 0 )); then
        log_error "run this smoke test with sudo so OBI can attach eBPF probes"
        return 1
    fi
    if [[ ! -x "$COLLECTOR_BINARY" ]]; then
        log_error "collector binary not found; build it with ocb before running this test"
        return 1
    fi
    if [[ ! -f "$CONFIG_PATH" ]]; then
        log_error "smoke configuration not found: $CONFIG_PATH"
        return 1
    fi
}

wait_for_http_server() {
    local -i attempt=0

    for ((attempt = 1; attempt <= 10; attempt += 1)); do
        if ! process_is_running "$SERVER_PID"; then
            log_error "HTTP server exited before becoming ready"
            return 1
        fi
        if curl --fail --silent --show-error --max-time 2 "$SMOKE_URL" >/dev/null; then
            return 0
        fi
        sleep 1
    done

    log_error "HTTP server did not become ready"
    return 1
}

wait_for_obi_trace() {
    local -i attempt=0

    for ((attempt = 1; attempt <= TRACE_ATTEMPTS; attempt += 1)); do
        if ! process_is_running "$COLLECTOR_PID"; then
            log_error "collector exited before exporting OBI telemetry"
            return 1
        fi

        curl --fail --silent --show-error --max-time 2 "$SMOKE_URL" >/dev/null
        if grep -Fq "ResourceSpans #0" "$COLLECTOR_LOG" &&
            grep -Eq "Name[[:space:]]*: GET /" "$COLLECTOR_LOG"; then
            return 0
        fi
        sleep 1
    done

    log_error "collector did not export an OBI HTTP trace within ${TRACE_ATTEMPTS}s"
    return 1
}

main() {
    if (( $# != 0 )); then
        log_error "this smoke test does not accept arguments"
        return 2
    fi

    check_dependencies
    check_inputs

    TMP_DIR="$(mktemp -d)"
    COLLECTOR_LOG="$TMP_DIR/collector.log"
    SERVER_LOG="$TMP_DIR/http-server.log"
    printf 'OBI Collector receiver smoke test\n' >"$TMP_DIR/index.html"

    python3 -m http.server "$SMOKE_PORT" --bind 127.0.0.1 \
        --directory "$TMP_DIR" >"$SERVER_LOG" 2>&1 &
    SERVER_PID="$!"
    wait_for_http_server

    "$COLLECTOR_BINARY" --config "$CONFIG_PATH" >"$COLLECTOR_LOG" 2>&1 &
    COLLECTOR_PID="$!"
    wait_for_obi_trace

    log_info "Config v2 receiver exported OBI HTTP trace telemetry"
}

trap 'on_error "$LINENO"' ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

main "$@"
