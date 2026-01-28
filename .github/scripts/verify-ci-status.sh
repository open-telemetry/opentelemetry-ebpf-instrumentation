#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Script to verify that all required CI checks passed on a commit before creating a release.
# This script queries GitHub's API to check the status of CI workflows and waits for
# in-progress checks to complete.

set -euo pipefail

# Immutable global variables.
PROGNAME="$(basename "$0")"
readonly PROGNAME
readonly MAX_WAIT_TIME=7200  # 2 hours in seconds.
readonly CHECK_INTERVAL=30   # Seconds between status checks.

# Required check patterns that must pass before release.
# GitHub's check-runs API returns individual job check names, not workflow names.
# Each pattern is a substring that matches job names from critical workflows.
readonly -a REQUIRED_CHECKS=(
  "shard-"                                # Unit and integration test shards.
  "kernel"                                # K8s integration test jobs.
  "daemonset"                             # OATS daemonset tests.
  "netolly"                               # OATS netolly tests.
  "lint markdown"                         # Markdown linting check.
)

# Print usage.
usage() {
  cat <<- EOF
Usage: $PROGNAME [OPTIONS] <repository> <commit-sha>

Verify that all required CI checks passed on a commit before creating a release.

Arguments:
  repository                 Repository in format "owner/repo"
  commit-sha                 Commit SHA to check

Required environment variables:
  GITHUB_TOKEN or GH_TOKEN   GitHub authentication token

Options:
  -h, --help                 Show this help message

Examples:
  GITHUB_TOKEN=\$TOKEN $PROGNAME open-telemetry/opentelemetry-ebpf-instrumentation abc123def
  GH_TOKEN=\$TOKEN $PROGNAME owner/repo \$GITHUB_SHA
  GH_TOKEN=\$(gh auth token) $PROGNAME \$REPOSITORY \$GITHUB_SHA

EOF
}

# Print error message and exit.
error_exit() {
  local message="$1"
  echo "ERROR: ${message}" >&2
  exit 1
}

# Check if variable is empty.
is_empty() {
  local var="$1"
  [[ -z "$var" ]]
}

# Check if variable is not empty.
is_not_empty() {
  local var="$1"
  [[ -n "$var" ]]
}

# Validate required environment variables.
validate_environment() {
  local gh_token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  
  if is_empty "$gh_token"; then
    error_exit "GITHUB_TOKEN or GH_TOKEN environment variable is required"
  fi
}

# Validate repository argument format.
validate_repository() {
  local repository="$1"
  
  if is_empty "$repository"; then
    error_exit "Repository argument is required"
  fi
  
  if ! [[ "$repository" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]; then
    error_exit "Repository must be in format 'owner/repo', got: $repository"
  fi
}

# Validate commit SHA argument.
validate_commit_sha() {
  local sha="$1"
  
  if is_empty "$sha"; then
    error_exit "Commit SHA argument is required"
  fi
  
  if ! [[ "$sha" =~ ^[a-f0-9]{7,40}$ ]]; then
    error_exit "Commit SHA must be a valid git SHA (7-40 hex characters), got: $sha"
  fi
}

# Fetch check runs for the commit from GitHub API.
fetch_check_runs() {
  local repository="$1"
  local sha="$2"
  
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "/repos/${repository}/commits/${sha}/check-runs" \
    --paginate
}

# Extract check run information from the API response.
# Returns "name|status|conclusion" for each check run.
extract_check_info() {
  local check_runs="$1"
  
  echo "$check_runs" \
    | jq -r '.check_runs[] | "\(.name)|\(.status)|\(.conclusion)"' \
    2>/dev/null || true
}

# Get all check runs matching a pattern (substring).
get_matching_checks() {
  local check_runs="$1"
  local pattern="$2"
  
  extract_check_info "$check_runs" \
    | grep -F "$pattern" || true
}

# Check if any check runs match a pattern.
has_matching_checks() {
  local check_runs="$1"
  local pattern="$2"
  
  get_matching_checks "$check_runs" "$pattern" | grep -q . && return 0 || return 1
}

# Check if all matching checks have passed (success or skipped).
all_matching_passed() {
  local check_runs="$1"
  local pattern="$2"
  
  local checks
  checks="$(get_matching_checks "$check_runs" "$pattern")"
  
  if is_empty "$checks"; then
    return 1  # No matching checks found.
  fi
  
  # Check each matching check status.
  while IFS='|' read -r _ status conclusion; do
    if [[ "$status" != "completed" ]]; then
      return 1  # Still in progress.
    fi
    if [[ "$conclusion" != "success" && "$conclusion" != "skipped" ]]; then
      return 1  # Failed.
    fi
  done <<< "$checks"
  
  return 0  # All matching checks passed.
}

# Check if any matching check has failed.
any_matching_failed() {
  local check_runs="$1"
  local pattern="$2"
  
  local checks
  checks="$(get_matching_checks "$check_runs" "$pattern")"
  
  while IFS='|' read -r _ status conclusion; do
    if [[ "$status" == "completed" && "$conclusion" != "success" && "$conclusion" != "skipped" ]]; then
      return 0  # Found a failed check.
    fi
  done <<< "$checks"
  
  return 1  # No failures found.
}

# Check if any matching check is still in progress.
any_matching_in_progress() {
  local check_runs="$1"
  local pattern="$2"
  
  local checks
  checks="$(get_matching_checks "$check_runs" "$pattern")"
  
  while IFS='|' read -r _ status conclusion; do
    if [[ "$status" != "completed" ]]; then
      return 0  # Found an in-progress check.
    fi
  done <<< "$checks"
  
  return 1  # None in progress.
}

# Print status of all required check patterns.
print_check_status() {
  local check_runs="$1"
  local pattern
  
  for pattern in "${REQUIRED_CHECKS[@]}"; do
    if ! has_matching_checks "$check_runs" "$pattern"; then
      echo "  ? $pattern - not found"
      continue
    fi
    
    local checks
    checks="$(get_matching_checks "$check_runs" "$pattern")"
    
    # Count statuses.
    local completed=0
    local in_progress=0
    local failed=0
    
    while IFS='|' read -r _ status conclusion; do
      if [[ "$status" == "completed" ]]; then
        if [[ "$conclusion" == "success" || "$conclusion" == "skipped" ]]; then
          ((completed++))
        else
          ((failed++))
        fi
      else
        ((in_progress++))
      fi
    done <<< "$checks"
    
    if [[ $failed -gt 0 ]]; then
      echo "  ✗ $pattern - $failed failed"
    elif [[ $in_progress -gt 0 ]]; then
      echo "  ⏳ $pattern - $in_progress in progress, $completed completed"
    elif [[ $completed -gt 0 ]]; then
      echo "  ✓ $pattern ($completed checks)"
    fi
  done
}

# Print final success status.
print_success() {
  local check_runs="$1"
  
  echo ""
  echo "✅ All required CI checks passed:"
  echo ""
  
  for pattern in "${REQUIRED_CHECKS[@]}"; do
    local count
    count="$(get_matching_checks "$check_runs" "$pattern" | wc -l)"
    if [[ $count -gt 0 ]]; then
      echo "  ✓ $pattern ($count checks passed)"
    fi
  done
  echo ""
}

# Check if all required patterns have at least one passing check.
all_patterns_passed() {
  local check_runs="$1"
  local pattern
  
  for pattern in "${REQUIRED_CHECKS[@]}"; do
    if ! all_matching_passed "$check_runs" "$pattern"; then
      return 1  # Pattern not satisfied.
    fi
  done
  
  return 0  # All patterns satisfied.
}

# Check if any required pattern is still in progress.
any_patterns_in_progress() {
  local check_runs="$1"
  local pattern
  
  for pattern in "${REQUIRED_CHECKS[@]}"; do
    if any_matching_in_progress "$check_runs" "$pattern"; then
      return 0  # Found pattern in progress.
    fi
  done
  
  return 1  # No patterns in progress.
}

# Check if any required pattern is missing checks.
any_patterns_missing() {
  local check_runs="$1"
  local pattern
  
  for pattern in "${REQUIRED_CHECKS[@]}"; do
    if ! has_matching_checks "$check_runs" "$pattern"; then
      return 0  # Pattern not found.
    fi
  done
  
  return 1  # All patterns found.
}

# Verify CI status with wait logic.
verify_ci_status() {
  local repository="$1"
  local sha="$2"
  local elapsed=0
  
  echo "Checking CI status for commit ${sha}"
  echo "Repository: ${repository}"
  echo ""
  
  while [[ $elapsed -lt $MAX_WAIT_TIME ]]; do
    local check_runs
    check_runs="$(fetch_check_runs "$repository" "$sha")"
    
    # If any required patterns have failed checks, stop immediately.
    local pattern
    for pattern in "${REQUIRED_CHECKS[@]}"; do
      if any_matching_failed "$check_runs" "$pattern"; then
        echo ""
        echo "❌ Some required checks have failed:"
        echo ""
        print_check_status "$check_runs"
        echo ""
        error_exit "Required checks failed. Please fix the failures before creating a release."
      fi
    done
    
    # If patterns are missing (never ran), fail on first check.
    if any_patterns_missing "$check_runs" && [[ $elapsed -eq 0 ]]; then
      echo ""
      echo "❌ Some required checks did not run on this commit:"
      echo ""
      print_check_status "$check_runs"
      echo ""
      error_exit "This usually means the tag was created from a commit that was not pushed to main. Please ensure the commit has gone through full CI on the main branch before tagging."
    fi
    
    # If all patterns have passing checks, we're done!
    if all_patterns_passed "$check_runs"; then
      print_success "$check_runs"
      return 0
    fi
    
    # Some checks still in progress, wait and retry.
    if any_patterns_in_progress "$check_runs"; then
      local minutes=$((elapsed / 60))
      echo "⏳ Some checks still in progress (waited ${minutes}m)..."
      echo ""
      print_check_status "$check_runs"
      echo ""
      echo "Waiting ${CHECK_INTERVAL}s before next check..."
      sleep "$CHECK_INTERVAL"
      elapsed=$((elapsed + CHECK_INTERVAL))
    fi
  done
  
  # Timeout reached.
  echo ""
  error_exit "Timeout waiting for CI checks to complete after $((MAX_WAIT_TIME / 60)) minutes. Some checks are still in progress. Please wait for CI to complete before releasing."
}

# Main function.
main() {
  local repository=""
  local commit_sha=""
  
  # Parse command line arguments.
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      -*)
        error_exit "Unknown option: $1. Use --help for usage information."
        ;;
      *)
        # Positional arguments.
        if is_empty "$repository"; then
          repository="$1"
        elif is_empty "$commit_sha"; then
          commit_sha="$1"
        else
          error_exit "Too many arguments. Expected: <repository> <commit-sha>"
        fi
        ;;
    esac
    shift
  done
  
  # Validate we have all required arguments
  if is_empty "$repository" || is_empty "$commit_sha"; then
    echo "ERROR: Missing required arguments" >&2
    echo "" >&2
    usage >&2
    exit 1
  fi
  
  # Validate environment
  validate_environment
  
  # Validate arguments
  validate_repository "$repository"
  validate_commit_sha "$commit_sha"
  
  # Run verification
  verify_ci_status "$repository" "$commit_sha"
}

# Run main function.
main "$@"
