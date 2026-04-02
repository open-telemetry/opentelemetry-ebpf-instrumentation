#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

PROGNAME="$(basename "$0")"
readonly PROGNAME
readonly DEFAULT_BASE_URL="http://127.0.0.1:8080"
readonly DEFAULT_PROGRESS_INTERVAL=15
readonly DEFAULT_CURL_TIMEOUT=10
readonly DEFAULT_INITIAL_DELAY_MS=250

declare -a WORKER_PIDS=()

usage() {
  cat <<EOF
Usage: $PROGNAME [options]

Exercise the nginx demo routes for the OBI example.

Options:
  -u, --base-url URL          Base URL for the edge nginx service.
                              Default: $DEFAULT_BASE_URL
  -o, --one-shot              Send a single pass across the full route set and exit.
  -p, --progress-seconds N    Print a progress summary every N seconds.
                              Default: $DEFAULT_PROGRESS_INTERVAL
  -t, --curl-timeout N        Per-request curl timeout in seconds.
                              Default: $DEFAULT_CURL_TIMEOUT
      --initial-delay-ms N    Maximum startup jitter per worker in milliseconds.
                              Default: $DEFAULT_INITIAL_DELAY_MS
  -h, --help                  Show this help text.

Examples:
  $PROGNAME
  $PROGNAME --base-url http://127.0.0.1:18080
  $PROGNAME --one-shot --base-url http://127.0.0.1:18080

In continuous mode the script runs until you stop it with Ctrl+C.
EOF
}

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

is_unsigned_integer() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]]
}

ms_to_seconds() {
  local milliseconds="$1"

  printf '%s.%03d' \
    "$((milliseconds / 1000))" \
    "$((milliseconds % 1000))"
}

log_info() {
  printf '[%(%Y-%m-%dT%H:%M:%S%z)T] %s\n' -1 "$*"
}

route_specs() {
  # Emit the full demo route set as path|expected_status|interval_ms records so
  # both one-shot and continuous modes share a single traffic definition.
  cat <<'EOF'
/users/42/home|200|4000
/campaigns/spring-2026/redirect|302|9000
/support/articles/984404|404|12000
/checkout/sessions/abc123xyz|500|15000
/api/users/42/recommendations/v1/homepage-hero|200|2500
/api/users/314159/recommendations/v1/category-bundles|404|10000
/api/users/271828/recommendations/v2/style-refresh|302|7000
/api/users/42/recommendations/rollout/personalized-homepage|200|3000
/api/users/9001/recommendations/rollout/cart-recovery|503|11000
EOF
}

fetch_http_code() {
  local output_var_name="$1"
  local path="$2"
  local curl_http_code

  if curl_http_code="$(
    curl \
      --silent \
      --show-error \
      --output /dev/null \
      --write-out '%{http_code}' \
      --max-time "$CURL_TIMEOUT" \
      "${BASE_URL}${path}"
  )"; then
    printf -v "$output_var_name" '%s' "$curl_http_code"
    return 0
  fi

  printf -v "$output_var_name" '%s' "${curl_http_code:-000}"
  return 1
}

request_route() {
  local path="$1"
  local expected_code="$2"
  local http_code=""

  fetch_http_code http_code "$path" || true

  if [[ "$http_code" == "$expected_code" ]]; then
    return 0
  fi

  printf 'expected %s but got %s for %s\n' \
    "$expected_code" \
    "$http_code" \
    "$path" >&2
  return 1
}

emit_event() {
  local fifo_path="$1"
  local event_type="$2"
  local path="$3"
  local observed_code="$4"
  local expected_code="$5"

  printf '%s\t%s\t%s\t%s\n' \
    "$event_type" \
    "$path" \
    "$observed_code" \
    "$expected_code" >"$fifo_path"
}

worker_loop() {
  local fifo_path="$1"
  local path="$2"
  local expected_code="$3"
  local interval_ms="$4"
  local startup_delay_ms=0
  local http_code=""

  trap 'exit 0' INT TERM

  if (( INITIAL_DELAY_MS > 0 )); then
    startup_delay_ms=$((RANDOM % (INITIAL_DELAY_MS + 1)))
    sleep "$(ms_to_seconds "$startup_delay_ms")"
  fi

  while true; do
    fetch_http_code http_code "$path" || true

    if [[ "$http_code" == "$expected_code" ]]; then
      emit_event "$fifo_path" "ok" "$path" "$http_code" "$expected_code"
    else
      emit_event "$fifo_path" "fail" "$path" "$http_code" "$expected_code"
    fi

    sleep "$(ms_to_seconds "$interval_ms")"
  done
}

parse_args() {
  local base_url="$DEFAULT_BASE_URL"
  local progress_interval="$DEFAULT_PROGRESS_INTERVAL"
  local curl_timeout="$DEFAULT_CURL_TIMEOUT"
  local initial_delay_ms="$DEFAULT_INITIAL_DELAY_MS"
  local one_shot=0

  while (($# > 0)); do
    case "$1" in
      -u|--base-url)
        (($# >= 2)) || die "missing value for $1"
        base_url="$2"
        shift 2
        ;;
      -o|--one-shot)
        one_shot=1
        shift
        ;;
      -p|--progress-seconds)
        (($# >= 2)) || die "missing value for $1"
        is_unsigned_integer "$2" || die "progress interval must be a non-negative integer"
        progress_interval="$2"
        shift 2
        ;;
      -t|--curl-timeout)
        (($# >= 2)) || die "missing value for $1"
        is_unsigned_integer "$2" || die "curl timeout must be a non-negative integer"
        curl_timeout="$2"
        shift 2
        ;;
      --initial-delay-ms)
        (($# >= 2)) || die "missing value for $1"
        is_unsigned_integer "$2" || die "initial delay must be a non-negative integer"
        initial_delay_ms="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        (($# == 0)) || die "unexpected positional arguments: $*"
        ;;
      -*)
        die "unknown option: $1"
        ;;
      *)
        die "unexpected positional argument: $1"
        ;;
    esac
  done

  declare -gr BASE_URL="$base_url"
  declare -gr PROGRESS_INTERVAL="$progress_interval"
  declare -gr CURL_TIMEOUT="$curl_timeout"
  declare -gr INITIAL_DELAY_MS="$initial_delay_ms"
  declare -gr ONE_SHOT="$one_shot"
}

cleanup() {
  local pid

  for pid in "${WORKER_PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done

  if [[ -n "${EVENT_FIFO:-}" && -p "${EVENT_FIFO:-}" ]]; then
    rm -f "$EVENT_FIFO"
  fi

  if [[ -n "${STATE_DIR:-}" && -d "${STATE_DIR:-}" ]]; then
    rm -rf "$STATE_DIR"
  fi
}

run_one_shot() {
  local path
  local expected_code
  local interval_ms
  local total=0

  log_info "sending one pass across the full route set"

  while IFS='|' read -r path expected_code interval_ms; do
    [[ -n "$path" ]] || continue
    total=$((total + 1))

    if request_route "$path" "$expected_code"; then
      printf '%-60s -> %s\n' "$path" "$expected_code"
    else
      return 1
    fi
  done < <(route_specs)

  log_info "completed one-shot run across $total routes"
}

print_progress() {
  local total_requests="$1"
  local total_failures="$2"
  local total_successes

  total_successes=$((total_requests - total_failures))

  log_info "progress: total=$total_requests success=$total_successes failures=$total_failures"
}

run_continuous() {
  local total_requests=0
  local total_failures=0
  local next_progress_at
  local path
  local expected_code
  local interval_ms
  local event_type
  local observed_code
  local event_expected_code

  STATE_DIR="$(mktemp -d)"
  readonly STATE_DIR
  EVENT_FIFO="$STATE_DIR/events.fifo"
  readonly EVENT_FIFO
  mkfifo "$EVENT_FIFO"
  exec 3<>"$EVENT_FIFO"

  while IFS='|' read -r path expected_code interval_ms; do
    [[ -n "$path" ]] || continue
    worker_loop "$EVENT_FIFO" "$path" "$expected_code" "$interval_ms" &
    WORKER_PIDS+=("$!")
  done < <(route_specs)

  log_info "starting continuous traffic against $BASE_URL"
  log_info "the route set is exercised concurrently at mixed rates; stop with Ctrl+C"

  next_progress_at=$((SECONDS + PROGRESS_INTERVAL))

  while true; do
    if IFS=$'\t' read -r -t 1 event_type path observed_code event_expected_code <&3; then
      total_requests=$((total_requests + 1))

      if [[ "$event_type" == "fail" ]]; then
        total_failures=$((total_failures + 1))
        log_info "request failed: path=$path expected=$event_expected_code got=$observed_code"
      fi
    fi

    if (( PROGRESS_INTERVAL > 0 && SECONDS >= next_progress_at )); then
      print_progress "$total_requests" "$total_failures"
      next_progress_at=$((SECONDS + PROGRESS_INTERVAL))
    fi
  done
}

main() {
  parse_args "$@"

  trap 'cleanup' EXIT
  trap 'log_info "received interrupt, shutting down"; exit 0' INT TERM

  if (( ONE_SHOT == 1 )); then
    run_one_shot
    return 0
  fi

  run_continuous
}

main "$@"
