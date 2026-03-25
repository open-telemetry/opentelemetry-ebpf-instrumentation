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
set -euo pipefail

PROGNAME="$(basename "$0")"
readonly PROGNAME
declare -ar ARGS=("$@")
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly DEFAULT_BASE_REF="main"
readonly DOCKERFILE_REGEX='(^|/)[^/]*Dockerfile[^/]*$'

usage() {
  cat <<EOF
Usage: ${PROGNAME} [--all|-a] [--base-ref <ref>|-b <ref>] [--verbose|-v]

Lints Dockerfiles against repository dependency integrity policy.

Options:
  --all, -a                 Lint all tracked Dockerfiles.
  --base-ref <ref>, -b <ref>
                            Base git ref for changed-file linting.
                            Default: CI PR base ref (if available), otherwise ${DEFAULT_BASE_REF}.
  --verbose, -v             Emit debug logs.
  -h, --help                Show this help message.
EOF
}

die() {
  local message="$1"
  printf 'ERROR: %s\n' "$message" >&2
  exit 1
}

debug_log() {
  local -i verbose="$1"
  local message="$2"

  (( verbose == 1 )) || return 0
  printf 'DEBUG: %s\n' "$message" >&2
}

on_error() {
  local lineno="$1"
  local exit_code="$2"
  local command_text="$3"

  printf 'ERROR: dependency-policy lint failed (exit=%s line=%s command=%s)\n' \
    "$exit_code" "$lineno" "$command_text" >&2
}

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
}

is_git_repo() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1
}

report_issue() {
  local file="$1"
  local line="$2"
  local message="$3"

  printf '%s:%s: %s\n' "$file" "$line" "$message" >&2
}

collect_files() {
  local -i lint_all_dockerfiles="$1"
  local base_ref="$2"
  local -i verbose="$3"
  local resolved_base_ref=""

  if (( lint_all_dockerfiles == 1 )); then
    git ls-files | grep -E "$DOCKERFILE_REGEX" || true
    return
  fi

  resolved_base_ref="$(resolve_base_ref_for_diff "$base_ref" "$verbose")"
  if [[ -n "$resolved_base_ref" ]]; then
    if git merge-base "$resolved_base_ref" HEAD >/dev/null 2>&1; then
      git --no-pager diff --name-only "${resolved_base_ref}...HEAD" | grep -E "$DOCKERFILE_REGEX" || true
      return
    fi

    debug_log "$verbose" "no merge-base for ${resolved_base_ref}...HEAD; using two-dot diff"
    git --no-pager diff --name-only "${resolved_base_ref}..HEAD" | grep -E "$DOCKERFILE_REGEX" || true
    return
  fi

  debug_log "$verbose" "unable to resolve base ref '${base_ref}'; falling back to all tracked Dockerfiles"
  git ls-files | grep -E "$DOCKERFILE_REGEX" || true
}

resolve_base_ref_for_diff() {
  # Base-ref resolution flow:
  # 1) Use a local ref if present (<base_ref>).
  # 2) Otherwise use remote-tracking ref if present (origin/<base_ref>).
  # 3) In GitHub Actions, shallow checkout may omit the PR base ref, so try a
  #    best-effort depth-1 fetch for origin/<base_ref>.
  # 4) If still unresolved (for example due to auth/network/permissions),
  #    return empty and let the caller apply its fallback behavior.
  local base_ref="$1"
  local -i verbose="$2"
  local remote_ref="origin/${base_ref}"

  if git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
    printf '%s\n' "$base_ref"
    return
  fi

  if git rev-parse --verify "$remote_ref" >/dev/null 2>&1; then
    printf '%s\n' "$remote_ref"
    return
  fi

  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    debug_log "$verbose" "fetching missing base ref from origin: ${base_ref}"
    if git fetch --no-tags --depth=1 origin "${base_ref}:${remote_ref}" >/dev/null 2>&1; then
      if git rev-parse --verify "$remote_ref" >/dev/null 2>&1; then
        printf '%s\n' "$remote_ref"
        return
      fi
    fi
  fi

  printf '\n'
}

lint_from_digest_pinning() {
  local file="$1"
  local -i verbose="$2"
  local line_num=""
  local reason=""
  local -i issues=0

  debug_log "$verbose" "file=${file} check=from-digest-pinning"

  while IFS='|' read -r line_num reason; do
    [[ -n "$line_num" ]] || continue

    case "$reason" in
      missing-digest)
        report_issue "$file" "$line_num" "FROM image is not digest-pinned (@sha256 missing)"
        (( issues += 1 ))
        ;;
      latest-tag)
        report_issue "$file" "$line_num" "FROM image uses :latest tag"
        (( issues += 1 ))
        ;;
      *)
        report_issue "$file" "$line_num" "FROM image violates policy"
        (( issues += 1 ))
        ;;
    esac
  done < <(
    awk '
      BEGIN { IGNORECASE=1 }
      function trim(s) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
        return s
      }

      function expand_arg_defaults(s, out, token, var_name, replacement, prev_out, iterations, self_ref_pattern) {
        out = s
        iterations = 0

        while (iterations < 128 && match(out, /\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*/)) {
          iterations++
          token = substr(out, RSTART, RLENGTH)

          if (substr(token, 1, 2) == "${") {
            var_name = substr(token, 3, length(token) - 3)
          } else {
            var_name = substr(token, 2)
          }

          if (var_name in arg_defaults) {
            replacement = arg_defaults[var_name]
          } else {
            break
          }

          if (replacement == token) {
            break
          }

          self_ref_pattern = "\\$\\{?" var_name "\\}?"
          if (replacement ~ self_ref_pattern) {
            break
          }

          prev_out = out
          out = substr(out, 1, RSTART - 1) replacement substr(out, RSTART + RLENGTH)

          if (out == prev_out) {
            break
          }
        }

        return out
      }

      /^[[:space:]]*ARG[[:space:]]+/ {
        text = $0
        sub(/^[[:space:]]*ARG[[:space:]]+/, "", text)
        text = trim(text)

        if (index(text, "=") > 0) {
          arg_name = trim(substr(text, 1, index(text, "=") - 1))
          arg_default = substr(text, index(text, "=") + 1)
          if (arg_name != "") {
            arg_defaults[arg_name] = arg_default
          }
        }
      }

      /^[[:space:]]*FROM[[:space:]]+/ {
        text = $0
        sub(/^[[:space:]]*FROM[[:space:]]+/, "", text)
        n = split(text, a, /[[:space:]]+/)
        i = 1
        if (a[i] ~ /^--platform=/) i++
        img = a[i]
        resolved_img = expand_arg_defaults(img)

        is_stage_ref = (img in stages)

        if (resolved_img != "scratch" && !is_stage_ref) {
          if (resolved_img !~ /@sha256:/) {
            printf "%d|missing-digest\n", NR
          }

          if (resolved_img ~ /:latest(@|$)/) {
            printf "%d|latest-tag\n", NR
          }
        }

        for (j = i + 1; j <= n; j++) {
          if (tolower(a[j]) == "as" && j < n) {
            stages[a[j + 1]] = 1
            break
          }
        }
      }
    ' "$file"
  )

  printf '%d\n' "$issues"
}

lint_go_latest_installs() {
  local file="$1"
  local -i verbose="$2"
  local line_num=""
  local -i issues=0

  debug_log "$verbose" "file=${file} check=go-latest-installs"

  while IFS=: read -r line_num _; do
    [[ -n "$line_num" ]] || continue
    report_issue "$file" "$line_num" "go install uses @latest"
    (( issues += 1 ))
  done < <(grep -nE '^[[:space:]]*RUN[[:space:]].*go[[:space:]]+install[[:space:]].*@latest' "$file" || true)

  printf '%d\n' "$issues"
}

lint_python_hashes() {
  local file="$1"
  local -i verbose="$2"
  local line_num=""
  local line_text=""
  local -i issues=0

  debug_log "$verbose" "file=${file} check=python-hashes"

  while IFS=: read -r line_num line_text; do
    [[ -n "$line_num" ]] || continue
    if [[ "$line_text" != *"--require-hashes"* ]]; then
      report_issue "$file" "$line_num" "pip install missing --require-hashes"
      (( issues += 1 ))
    fi
  done < <(grep -nE '^[[:space:]]*RUN[[:space:]].*pip(3)?[[:space:]]+install[[:space:]]' "$file" || true)

  printf '%d\n' "$issues"
}

lint_node_mutable_installs() {
  local file="$1"
  local -i verbose="$2"
  local line_num=""
  local -i issues=0

  debug_log "$verbose" "file=${file} check=node-mutable-installs"

  while IFS=: read -r line_num _; do
    [[ -n "$line_num" ]] || continue
    report_issue "$file" "$line_num" "mutable npm install found; use npm ci"
    (( issues += 1 ))
  done < <(grep -nE '^[[:space:]]*RUN[[:space:]].*npm[[:space:]]+install([[:space:]]|$)' "$file" || true)

  while IFS=: read -r line_num _; do
    [[ -n "$line_num" ]] || continue
    report_issue "$file" "$line_num" "npm init found in Dockerfile"
    (( issues += 1 ))
  done < <(grep -nE '^[[:space:]]*RUN[[:space:]].*npm[[:space:]]+init([[:space:]]|$)' "$file" || true)

  printf '%d\n' "$issues"
}

lint_rust_locked_builds() {
  local file="$1"
  local -i verbose="$2"
  local line_num=""
  local line_text=""
  local -i issues=0

  debug_log "$verbose" "file=${file} check=rust-locked-builds"

  while IFS=: read -r line_num line_text; do
    [[ -n "$line_num" ]] || continue
    if [[ "$line_text" != *"--locked"* ]]; then
      report_issue "$file" "$line_num" "cargo build missing --locked"
      (( issues += 1 ))
    fi
  done < <(grep -nE '^[[:space:]]*RUN[[:space:]].*cargo[[:space:]]+build([[:space:]]|$)' "$file" || true)

  printf '%d\n' "$issues"
}

lint_no_pipe_to_shell() {
  local file="$1"
  local -i verbose="$2"
  local line_num=""
  local -i issues=0

  debug_log "$verbose" "file=${file} check=no-pipe-to-shell"

  while IFS=: read -r line_num _; do
    [[ -n "$line_num" ]] || continue
    report_issue "$file" "$line_num" "curl pipe-to-shell pattern detected"
    (( issues += 1 ))
  done < <(grep -nE '^[[:space:]]*RUN[[:space:]].*curl[^|]*\|[[:space:]]*(bash|sh)([[:space:]]|$)' "$file" || true)

  printf '%d\n' "$issues"
}

lint_file() {
  local file="$1"
  local -i verbose="$2"
  local -i issues=0
  local -i check_issues=0

  debug_log "$verbose" "linting file=${file}"

  if [[ ! -f "$file" ]]; then
    printf '0\n'
    return
  fi

  check_issues="$(lint_from_digest_pinning "$file" "$verbose")"
  issues=$((issues + check_issues))

  check_issues="$(lint_go_latest_installs "$file" "$verbose")"
  issues=$((issues + check_issues))

  check_issues="$(lint_python_hashes "$file" "$verbose")"
  issues=$((issues + check_issues))

  check_issues="$(lint_node_mutable_installs "$file" "$verbose")"
  issues=$((issues + check_issues))

  check_issues="$(lint_rust_locked_builds "$file" "$verbose")"
  issues=$((issues + check_issues))

  check_issues="$(lint_no_pipe_to_shell "$file" "$verbose")"
  issues=$((issues + check_issues))

  printf '%d\n' "$issues"
}

derive_base_ref() {
  if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    printf '%s\n' "$GITHUB_BASE_REF"
    return
  fi

  printf '%s\n' "$DEFAULT_BASE_REF"
}

cmdline() {
  local -i out_lint_all=0
  local out_base_ref=""
  local -i out_base_ref_set=0
  local -i out_verbose=0

  while (( $# > 0 )); do
    case "$1" in
      --all|-a)
        out_lint_all=1
        ;;
      --base-ref|-b)
        shift
        if (( $# == 0 )); then
          die "--base-ref requires a value"
        fi
        out_base_ref="$1"
        out_base_ref_set=1
        ;;
      --base-ref=*)
        if [[ -z "${1#*=}" ]]; then
          die "--base-ref requires a non-empty value"
        fi
        out_base_ref="${1#*=}"
        out_base_ref_set=1
        ;;
      --verbose|-v)
        out_verbose=1
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      --)
        shift
        if (( $# > 0 )); then
          die "unexpected positional arguments: $*"
        fi
        break
        ;;
      -*)
        die "unknown argument: $1"
        ;;
      *)
        die "unexpected positional argument: $1"
        ;;
    esac

    shift
  done

  printf '%s|%s|%s|%s\n' "$out_lint_all" "$out_base_ref" "$out_base_ref_set" "$out_verbose"
}

main() {
  local -i lint_all_dockerfiles=0
  local base_ref=""
  local -i base_ref_set=0
  local -i verbose=0
  local cmdline_result=""
  local -i fail_count=0
  local -i file_issues=0
  local -a files=()
  local file=""

  trap 'on_error "${LINENO}" "$?" "${BASH_COMMAND}"' ERR

  require_command git
  require_command awk
  require_command grep
  require_command sort

  cmdline_result="$(cmdline "$@")"
  IFS='|' read -r lint_all_dockerfiles base_ref base_ref_set verbose <<< "$cmdline_result"
  if (( base_ref_set == 0 )); then
    base_ref="$(derive_base_ref)"
  fi

  debug_log "$verbose" "base-ref=${base_ref} source=$([[ ${base_ref_set} -eq 1 ]] && echo cli || echo env/default)"
  debug_log "$verbose" "using awk=$(command -v awk)"

  cd "$ROOT_DIR"

  is_git_repo || die "must be run from within a git repository"

  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    files+=("$file")
  done < <(collect_files "$lint_all_dockerfiles" "$base_ref" "$verbose" | sort -u)

  if [[ ${#files[@]} -eq 0 ]]; then
    echo "No Dockerfiles to lint."
    exit 0
  fi

  for file in "${files[@]}"; do
    file_issues="$(lint_file "$file" "$verbose")"
    fail_count=$((fail_count + file_issues))
  done

  if (( fail_count > 0 )); then
    echo "Dependency policy lint failed with ${fail_count} issue(s)."
    exit 1
  fi

  echo "Dependency policy lint passed for ${#files[@]} Dockerfile(s)."
}

main "${ARGS[@]}"
