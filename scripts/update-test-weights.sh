#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Regenerate integration-test-weights.generated.json from the gotestsum JSON
# reports uploaded by the "Integration tests" workflow.
#
# Usage:
#   ./scripts/update-test-weights.sh [reports-directory]
#
# With a directory, every *.log under it whose path contains "-$ARCH-" is read.
# Without one, the integration-reports artifacts of the last $RUNS completed
# push runs on main created within the last $RETENTION_DAYS days are downloaded
# with the gh CLI. Failed and timed-out runs count too: skipping them would
# leave out exactly the slow runs.
#
# Docker caches an image within a shard, so a build shared by several suites
# costs only the first suite that runs it. That depends on the order, not the
# suite, so each suite instead gets an even share of its shared images' cold
# build time, read from the "built compose services" lines of the reports.
# Those name each build by tag and a digest of its resolved definition, so a tag
# reused for another Dockerfile or build argument counts as a different build.
#
# Environment:
#   ARCH  - architecture whose reports are used (default: amd64)
#   RUNS  - maximum number of main runs to download (default: 10)
#   RETENTION_DAYS - artifact retention of the reports (default: 5)
#   GITHUB_REPOSITORY - owner/repo to download from (default: the gh default repo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEIGHTS_FILE="$SCRIPT_DIR/integration-test-weights.generated.json"
DEFAULT_WEIGHT=20
ARCH="${ARCH:-amd64}"
RUNS="${RUNS:-10}"
RETENTION_DAYS="${RETENTION_DAYS:-5}"
RUNS_USED=""

for command_name in jq find; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Error: missing required command: $command_name" >&2
        exit 1
    fi
done

if [ $# -ge 1 ]; then
    REPORTS_DIR="$1"
    if [ ! -d "$REPORTS_DIR" ]; then
        echo "Error: '$REPORTS_DIR' is not a directory" >&2
        exit 1
    fi
else
    if ! command -v gh >/dev/null 2>&1; then
        echo "Error: gh is required when no reports directory is given" >&2
        exit 1
    fi
    for name in RUNS RETENTION_DAYS; do
        if ! [[ "${!name}" =~ ^[1-9][0-9]*$ ]]; then
            echo "Error: $name must be a positive integer, got '${!name}'" >&2
            exit 1
        fi
    done
    if date --version >/dev/null 2>&1; then
        cutoff="$(date -u -d "-${RETENTION_DAYS} days" +%Y-%m-%dT%H:%M:%SZ)"
    else
        cutoff="$(date -u -v-"${RETENTION_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)"
    fi
    REPORTS_DIR="$(mktemp -d)"
    trap 'rm -rf "$REPORTS_DIR"' EXIT
    repo_args=()
    if [ -n "${GITHUB_REPOSITORY:-}" ]; then
        repo_args=(--repo "$GITHUB_REPOSITORY")
    fi
    run_ids="$(gh run list "${repo_args[@]}" \
        --workflow pull_request_integration_tests.yml \
        --branch main --event push --status completed \
        --limit 100 --json databaseId,createdAt,conclusion \
        --jq "[.[] | select(.createdAt >= \"$cutoff\" and (.conclusion == \"success\" or .conclusion == \"failure\" or .conclusion == \"cancelled\"))][:$RUNS][].databaseId")"
    if [ -z "$run_ids" ]; then
        echo "Error: no completed main runs since $cutoff (reports expire after $RETENTION_DAYS days)" >&2
        exit 1
    fi
    RUNS_USED=0
    for run_id in $run_ids; do
        if gh run download "$run_id" "${repo_args[@]}" \
            --pattern "integration-reports-*-$ARCH-*" \
            --dir "$REPORTS_DIR/$run_id" >&2; then
            RUNS_USED=$((RUNS_USED + 1))
        else
            echo "Warning: no reports downloaded for run $run_id" >&2
        fi
    done
fi

mapfile -t report_files < <(find "$REPORTS_DIR" -type f -name '*.log' -path "*-$ARCH-*")
if [ "${#report_files[@]}" -eq 0 ]; then
    echo "Error: no reports matching '*-$ARCH-*/*.log' found in '$REPORTS_DIR'" >&2
    exit 1
fi

# One sample per passing suite and report, with the compose builds the suite ran.
SAMPLES="$(
    for report in "${report_files[@]}"; do
        jq -R -s -c '
            [split("\n")[] | fromjson? | select(
                ((.Package // "") | endswith("internal/test/integration")) and ((.Test // "") != "")
            )] as $events
            | ([$events[] | select(.Action == "output")
                | {suite: (.Test | split("/")[0]),
                   build: (.Output | capture("built compose services seconds=(?<seconds>[0-9]+) images=(?<images>[^ \n]*)"))}
                | {suite, seconds: (.build.seconds | tonumber), images: (.build.images | split(",") | map(select(. != "")))}
              ] | group_by(.suite) | map({key: .[0].suite, value: map({seconds, images})}) | from_entries) as $builds
            | $events[] | select(.Action == "pass" and (.Test | test("^Test[^/]*$")))
            | {name: .Test, elapsed: .Elapsed, builds: ($builds[.Test] // [])}
        ' "$report"
    done
)"

WEIGHTS="$(
    jq -s --argjson default "$DEFAULT_WEIGHT" '
        def median: sort | if length % 2 == 1 then .[(length - 1) / 2]
                           else (.[length / 2 - 1] + .[length / 2]) / 2 end;

        # every build splits its time evenly over the images it built
        [.[] | .name as $suite | .builds[] | (.seconds / ([.images | length, 1] | max)) as $share
             | .images[] | {image: ., suite: $suite, share: $share}] as $shares
        | ($shares | group_by(.image) | map({key: .[0].image, value: (map(.suite) | unique | length)})
                   | from_entries) as $suites
        | ($shares | group_by(.image) | map({key: .[0].image, value: (map(.share) | max)}) | from_entries) as $cold
        | def shared: $suites[.] > 1;

        group_by(.name)
        | map({
            key: .[0].name,
            value: (
                (map(.elapsed - ([.builds[] | (.seconds / ([.images | length, 1] | max)) as $share
                                  | .images[] | select(shared) | $share] | add // 0)) | median)
                + ([.[].builds[].images[] | select(shared)] | unique
                   | map($cold[.] / $suites[.]) | add // 0)
                | if . < 0 then 0 else . end | round)
          })
        | {_default: $default} + from_entries' <<< "$SAMPLES"
)"

TOTAL="$(jq 'length - 1' <<< "$WEIGHTS")"
if [ "$TOTAL" -eq 0 ]; then
    echo "Error: no passing top-level integration tests found in ${#report_files[@]} reports" >&2
    exit 1
fi

jq --indent 2 . <<< "$WEIGHTS" > "$WEIGHTS_FILE"
echo "Updated $WEIGHTS_FILE" >&2
echo "$TOTAL test weights from ${#report_files[@]} $ARCH shard reports${RUNS_USED:+ of $RUNS_USED main runs since $cutoff}."
