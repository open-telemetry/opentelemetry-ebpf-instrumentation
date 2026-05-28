#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# PoC: process per-shard bpftool snapshots into a markdown report + JSON
# sidecar. When a gotestsum json log is provided, also produces per-suite
# attribution showing which top-level tests are the heaviest eBPF consumers.
#
# Usage:
#   bpf-metrics-summary.sh --in <snapshot_dir> [--testlog <gotestsum.jsonl>] [--out-json <file>]
#
# Emits markdown to $GITHUB_STEP_SUMMARY (or stdout). Optionally writes a
# machine-readable JSON sidecar for downstream aggregation/rollup.

set -euo pipefail

IN_DIR=""
TEST_LOG=""
OUT_JSON=""
SHARD_LABEL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN_DIR="$2"; shift 2 ;;
    --testlog) TEST_LOG="$2"; shift 2 ;;
    --out-json) OUT_JSON="$2"; shift 2 ;;
    --shard) SHARD_LABEL="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$IN_DIR" ]; then
  IN_DIR="${1:-/tmp/bpfsamples}"
fi

emit() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  else
    printf '%s\n' "$1"
  fi
}

iso_utc() {
  # GNU date (Linux) accepts -d; BSD date (macOS) uses -r. Fall back to the
  # raw unix timestamp only if neither form is available.
  date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || echo "$1"
}

shopt -s nullglob
snapshots=("$IN_DIR"/snap-*.json)

if [ ${#snapshots[@]} -eq 0 ]; then
  emit "## bpftool snapshot${SHARD_LABEL:+ (shard $SHARD_LABEL)}"
  emit ""
  emit "_No snapshots found in \`$IN_DIR\`._"
  if [ -n "$OUT_JSON" ]; then
    printf '{"shard":"%s","snapshots":0,"suites":[]}\n' "$SHARD_LABEL" > "$OUT_JSON"
  fi
  exit 0
fi

# Build a per-snapshot index of total bytes_memlock keyed by ts.
# Format: one line per snapshot: "<ts> <total_bytes>"
SNAP_INDEX=$(mktemp)
trap 'rm -f "$SNAP_INDEX"' EXIT

for f in "${snapshots[@]}"; do
  total=$(jq '[.maps[]?.bytes_memlock // 0] | add // 0' "$f" 2>/dev/null || echo 0)
  ts=$(jq -r '.ts' "$f" 2>/dev/null || basename "$f" | sed 's/snap-//;s/.json//')
  printf '%s %s %s\n' "$ts" "$total" "$f"
done | sort -n > "$SNAP_INDEX"

# Peak snapshot across the whole shard (for top-N maps/progs).
peak_line=$(sort -k2,2 -n "$SNAP_INDEX" | tail -1)
peak_total=$(awk '{print $2}' <<< "$peak_line")
peak_snapshot=$(awk '{print $3}' <<< "$peak_line")
peak_ts=$(awk '{print $1}' <<< "$peak_line")
first_ts=$(head -1 "$SNAP_INDEX" | awk '{print $1}')
last_ts=$(tail -1 "$SNAP_INDEX" | awk '{print $1}')
sample_count=${#snapshots[@]}
peak_mib=$(awk -v t="$peak_total" 'BEGIN{printf "%.2f", t/1024/1024}')

# Convert byte values to MiB for jq pipelines below.
b2mib='(./1024/1024 * 100 | round / 100)'

# Suite-level attribution (optional): parse gotestsum jsonfile if given.
# Top-level tests are .Test values that contain no '/'. We collect each
# such test's [start_ts, end_ts] then bucket snapshots into those windows.
SUITES_JSON="[]"
if [ -n "$TEST_LOG" ] && [ -f "$TEST_LOG" ]; then
  # Build per-suite { name, start, end } from gotestsum events.
  SUITE_WINDOWS=$(jq -s -r '
    map(select(.Test != null and (.Test | contains("/") | not)))
    | group_by(.Test)
    | map({
        name: .[0].Test,
        start: (map(select(.Action == "run")) | .[0].Time // null),
        end:   (map(select(.Action == "pass" or .Action == "fail" or .Action == "skip")) | .[0].Time // null),
        result: (map(select(.Action == "pass" or .Action == "fail" or .Action == "skip")) | .[0].Action // "unknown")
      })
    | map(select(.start != null))
  ' < <(jq -c 'select(.Test != null and (.Action == "run" or .Action == "pass" or .Action == "fail" or .Action == "skip"))' "$TEST_LOG"))

  # For each suite window, find snapshot totals within and compute stats.
  # We pass the snapshot index in via --rawfile and parse it inside jq.
  SUITES_JSON=$(jq --rawfile snaps "$SNAP_INDEX" '
    def parse_ts: sub("\\.[0-9]+"; "") | fromdateiso8601;
    def snap_lines: $snaps | split("\n") | map(select(length > 0));
    def snap_series:
      snap_lines | map(split(" ") | { ts: (.[0] | tonumber), total: (.[1] | tonumber) });
    . as $suites
    | snap_series as $series
    | $suites
    | map(
        .start_ts = (.start | parse_ts)
        | .end_ts = (if .end then (.end | parse_ts) else .start_ts end)
        | .duration_s = (.end_ts - .start_ts)
      )
    | map(
        . as $s
        | ($series | map(select(.ts >= $s.start_ts and .ts <= $s.end_ts))) as $window
        | .snapshots_in_window = ($window | length)
        | .peak_bytes = ($window | map(.total) | max // 0)
        | .series = ($window | map(.total))
      )
    | map(del(.start_ts, .end_ts))
  ' <<< "$SUITE_WINDOWS")
fi

# Sparkline encoder: takes a JSON array of numbers via stdin, emits a string.
sparkline_from_json() {
  jq -r '
    if length == 0 then ""
    else
      . as $vals
      | ($vals | min) as $lo
      | ($vals | max) as $hi
      | ($hi - $lo) as $rng
      | ["▁","▂","▃","▄","▅","▆","▇","█"] as $chars
      | $vals
      | map(
          if $rng == 0 then 3
          else ((. - $lo) / $rng * 7) | floor
          end
          | $chars[.]
        )
      | join("")
    end
  '
}

# --- Markdown output ---

emit "## bpftool snapshot${SHARD_LABEL:+ (shard $SHARD_LABEL)}"
emit ""
emit "_Data source: \`bpftool map show -j\` + \`bpftool prog show -j\`._"
emit "_Future data sources for this section may include bpftop and OBI's own internal metrics._"
emit ""
emit "**Shard overview**"
emit ""
emit "| metric | value |"
emit "| --- | ---: |"
emit "| snapshots | $sample_count |"
emit "| window (UTC) | $(iso_utc "$first_ts") → $(iso_utc "$last_ts") |"
emit "| peak memlock (MiB) | $peak_mib |"
emit "| peak (UTC) | $(iso_utc "$peak_ts") |"
emit "| maps at peak | $(jq '.maps | length' "$peak_snapshot") |"
emit "| programs at peak | $(jq '.progs | length' "$peak_snapshot") |"
emit ""

# Per-suite table (only if we have test attribution).
if [ "$(jq 'length' <<< "$SUITES_JSON")" -gt 0 ]; then
  emit "### Top suites by peak memlock"
  emit ""
  emit "| suite | duration (s) | peak memlock (MiB) | snapshots in window | trend |"
  emit "| --- | ---: | ---: | ---: | --- |"

  # Build rows sorted by peak descending. Skip suites with no snapshots in window.
  rows=$(jq -r '
    map(select(.snapshots_in_window > 0))
    | sort_by(-.peak_bytes)
    | .[]
    | [
        .name,
        (.duration_s // 0),
        (.peak_bytes / 1024 / 1024 * 100 | round / 100),
        .snapshots_in_window,
        (.series | tojson)
      ] | @tsv
  ' <<< "$SUITES_JSON")

  while IFS=$'\t' read -r name duration_s peak_mib_v snaps_v series_json; do
    spark=$(sparkline_from_json <<< "$series_json")
    emit "| \`$name\` | $duration_s | $peak_mib_v | $snaps_v | $spark |"
  done <<< "$rows"
  emit ""
fi

# Group peak-snapshot maps & progs by name once, used by both markdown
# and the JSON sidecar (so the aggregator can merge across shards).
PEAK_MAPS_GROUPED=$(jq '
  .maps
  | group_by(.name // "<unnamed>")
  | map({
      name: (.[0].name // "<unnamed>"),
      type: (.[0].type // "?"),
      count: length,
      total_memlock: ([.[].bytes_memlock // 0] | add),
      max_entries: ([.[].max_entries // 0] | max)
    })
  | sort_by(-.total_memlock)
' "$peak_snapshot")

PEAK_PROGS_GROUPED=$(jq '
  .progs
  | group_by(.name // "<unnamed>")
  | map({
      name: (.[0].name // "<unnamed>"),
      type: (.[0].type // "?"),
      count: length,
      total_run_cnt: ([.[].run_cnt // 0] | add),
      total_run_time_ns: ([.[].run_time_ns // 0] | add)
    })
  | sort_by(-.total_run_time_ns)
' "$peak_snapshot")

emit "<details><summary>Top 20 maps at peak (by total bytes_memlock)</summary>"
emit ""
emit "_Map names are limited to 15 characters by the kernel's \`BPF_OBJ_NAME_LEN\`. The \`count\` column shows how many distinct map instances share that truncated name (typically one per OBI process running concurrently)._"
emit ""
emit "| name | type | count | total bytes_memlock (MiB) | max_entries |"
emit "| --- | --- | ---: | ---: | ---: |"

while IFS= read -r line; do emit "$line"; done < <(jq -r '
  .[0:20]
  | .[]
  | "| \(.name) | \(.type) | \(.count) | \((.total_memlock / 1024 / 1024 * 100 | round / 100)) | \(.max_entries) |"
' <<< "$PEAK_MAPS_GROUPED")

emit ""
emit "</details>"
emit ""

emit "<details><summary>Top 10 programs at peak (by run_time_ns)</summary>"
emit ""
emit "| name | type | count | total run_cnt | total run_time_ns |"
emit "| --- | --- | ---: | ---: | ---: |"

while IFS= read -r line; do emit "$line"; done < <(jq -r '
  .[0:10]
  | .[]
  | "| \(.name) | \(.type) | \(.count) | \(.total_run_cnt) | \(.total_run_time_ns) |"
' <<< "$PEAK_PROGS_GROUPED")

emit ""
emit "</details>"

# --- JSON sidecar ---

if [ -n "$OUT_JSON" ]; then
  jq -n \
    --arg shard "$SHARD_LABEL" \
    --argjson sample_count "$sample_count" \
    --argjson first_ts "$first_ts" \
    --argjson last_ts "$last_ts" \
    --argjson peak_bytes "$peak_total" \
    --argjson peak_ts "$peak_ts" \
    --argjson suites "$SUITES_JSON" \
    --argjson peak_maps "$PEAK_MAPS_GROUPED" \
    --argjson peak_progs "$PEAK_PROGS_GROUPED" \
    --slurpfile peak_snap "$peak_snapshot" \
    '{
       shard: $shard,
       snapshots: $sample_count,
       window: { start: $first_ts, end: $last_ts },
       peak: {
         ts: $peak_ts,
         total_bytes_memlock: $peak_bytes,
         maps: ($peak_snap[0].maps | length),
         progs: ($peak_snap[0].progs | length),
         maps_grouped: $peak_maps,
         progs_grouped: $peak_progs
       },
       suites: $suites
     }' > "$OUT_JSON"
fi
