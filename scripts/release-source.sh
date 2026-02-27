#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
readonly PROGNAME

DEFAULT_RELEASE_DIR="./dist"
readonly DEFAULT_RELEASE_DIR

# Used only when HEAD is detached (not on a branch or tag).
DETACHED_HEAD_FALLBACK_VERSION="main"
readonly DETACHED_HEAD_FALLBACK_VERSION

GENERATED_PATTERN='_bpfe[lb]\.go$|_bpfe[lb]\.o$|_bpfe[lb]\.go\.d$'
readonly GENERATED_PATTERN

usage() {
  cat <<EOF
Usage: $PROGNAME [--release-version <version>] [--release-dir <dir>] [--debug|-x] [--help|-h]

Builds source-generated release archive with generated bpf2go artifacts.

Options:
  --release-version  Release version/tag to archive (default: exact tag or main)
  --release-dir      Output directory (default: ./dist)
  -x, --debug   Preserve temporary files for debugging
  -h, --help    Show this help message

Environment:
  TMPDIR                Temporary directory base
EOF
}

parse_args() {
  local default_release_version
  local default_release_dir
  local debug_mode=""
  local release_version=""
  local release_dir=""
  local arg=""

  default_release_version="$(resolve_default_release_version)"
  default_release_dir="$DEFAULT_RELEASE_DIR"

  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      --release-version)
        shift
        [[ $# -gt 0 ]] || die "missing value for --release-version"
        release_version="$1"
        ;;
      --release-dir)
        shift
        [[ $# -gt 0 ]] || die "missing value for --release-dir"
        release_dir="$1"
        ;;
      -x|--debug)
        debug_mode="1"
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $arg"
        ;;
    esac
    shift
  done

  [[ -n "$release_version" ]] || release_version="$default_release_version"
  [[ -n "$release_dir" ]] || release_dir="$default_release_dir"
  [[ -n "$debug_mode" ]] || debug_mode="0"

  readonly RELEASE_VERSION_ARG="$release_version"
  readonly RELEASE_DIR_ARG="$release_dir"
  readonly RELEASE_SOURCE_DEBUG_ARG="$debug_mode"
}

log_info() {
  local message="$1"
  printf '%s\n' "$message"
}

log_error() {
  local message="$1"
  printf 'ERROR: %s\n' "$message" >&2
}

die() {
  local message="$1"
  log_error "$message"
  exit 1
}

require_cmd() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 \
    || die "required command not found: $command_name"
}

cleanup() {
  local source_root="$1"
  local generated_files="$2"
  local debug_mode="$3"

  if [[ "$debug_mode" == "1" ]]; then
    log_info "Debug mode enabled; preserving temp files:"
    log_info "  source_root=$source_root"
    log_info "  generated_files=$generated_files"
    return
  fi

  [[ -n "$source_root" ]] && rm -rf "$source_root"
  [[ -n "$generated_files" ]] && rm -f "$generated_files"
}

resolve_default_release_version() {
  local tag=""
  local branch=""
  if tag="$(git describe --tags --exact-match 2>/dev/null)"; then
    printf '%s\n' "$tag"
    return
  fi

  if branch="$(git symbolic-ref --short -q HEAD 2>/dev/null)"; then
    printf '%s\n' "$branch"
    return
  fi

  printf '%s\n' "$DETACHED_HEAD_FALLBACK_VERSION"
}

create_temp_dir() {
  local base_dir="$1"
  mktemp -d "$base_dir/obi-source.XXXXXX"
}

create_temp_file() {
  local base_dir="$1"
  mktemp "$base_dir/obi-generated.XXXXXX"
}

collect_generated_files() {
  local destination_file="$1"

  find pkg -type f \
    \( \
      -name '*_bpfe[lb].go' \
      -o -name '*_bpfe[lb].o' \
      -o -name '*_bpfe[lb].go.d' \
    \) \
    | sort -u > "$destination_file"
}

copy_generated_files() {
  local source_dir="$1"
  local generated_file_list="$2"
  local generated_count=0
  local path=""

  while IFS= read -r path; do
    [[ -z "$path" ]] && continue

    if [[ -f "$path" || -L "$path" ]]; then
      mkdir -p "$source_dir/$(dirname "$path")"
      cp -a "$path" "$source_dir/$path"
      generated_count=$((generated_count + 1))
    fi
  done < "$generated_file_list"

  printf '%s\n' "$generated_count"
}

count_generated_in_archive() {
  local archive_path="$1"
  tar -tf "$archive_path" | grep -Ec "$GENERATED_PATTERN" || true
}

main() {
  local source_root
  local source_basename
  local source_dir
  local generated_files
  local temp_base_dir
  local archive_path
  local generated_count
  local tar_generated_count

  parse_args "$@"

  require_cmd git
  require_cmd tar
  require_cmd find
  require_cmd grep
  require_cmd cp
  require_cmd mktemp

  log_info "### Building source-generated release archive"
  mkdir -p "$RELEASE_DIR_ARG"

  temp_base_dir="${TMPDIR:-/tmp}"
  source_root="$(create_temp_dir "$temp_base_dir")"
  generated_files="$(create_temp_file "$temp_base_dir")"
  readonly RELEASE_SOURCE_ROOT_ARG="$source_root"
  readonly RELEASE_GENERATED_FILES_ARG="$generated_files"
  source_basename="obi-${RELEASE_VERSION_ARG}-source-generated"
  source_dir="$source_root/$source_basename"

  trap 'cleanup "$RELEASE_SOURCE_ROOT_ARG" "$RELEASE_GENERATED_FILES_ARG" "$RELEASE_SOURCE_DEBUG_ARG"' EXIT

  mkdir -p "$source_dir"
  git archive --format=tar "$RELEASE_VERSION_ARG" | tar -xf - -C "$source_dir"

  collect_generated_files "$generated_files"
  generated_count="$(copy_generated_files "$source_dir" "$generated_files")"

  if [[ "$generated_count" -eq 0 ]]; then
    die "no generated bpf2go artifacts found to include in source archive"
  fi
  log_info "Added ${generated_count} generated files to source archive"

  archive_path="$RELEASE_DIR_ARG/obi-${RELEASE_VERSION_ARG}-source-generated.tar.gz"
  rm -f "$RELEASE_DIR_ARG"/obi-*-source-generated.tar.gz
  tar -czf "$archive_path" -C "$source_root" "$source_basename"

  tar_generated_count="$(count_generated_in_archive "$archive_path")"
  if [[ "$tar_generated_count" -eq 0 ]]; then
    die "source archive does not contain generated bpf2go artifacts"
  fi
  log_info "Verified ${tar_generated_count} generated bpf2go artifacts in source archive"
}

main "$@"
