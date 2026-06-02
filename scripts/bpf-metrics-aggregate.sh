#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# PoC: aggregate per-shard summary JSON sidecars (produced by
# bpf-metrics-summary.sh --out-json) into a single workflow-level report.
#
# Usage:
#   bpf-metrics-aggregate.sh --in <dir-of-shard-dirs> --out-md <file> --out-json <file>
#
# Input layout (as produced by actions/download-artifact with a pattern):
#   <in>/bpf-metrics-<shard>-<run>/summary.json
#   <in>/bpf-metrics-<shard>-<run>/snap-*.json (ignored here)

set -euo pipefail

IN_DIR=""
OUT_MD=""
OUT_JSON=""

while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN_DIR="$2"; shift 2 ;;
    --out-md) OUT_MD="$2"; shift 2 ;;
    --out-json) OUT_JSON="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

IN_DIR="${IN_DIR:-./all-shards}"
OUT_MD="${OUT_MD:-/tmp/bpf-metrics-aggregate.md}"

: > "$OUT_MD"

emit() {
  printf '%s\n' "$1" >> "$OUT_MD"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

shopt -s nullglob
summaries=("$IN_DIR"/*/summary.json)

if [ ${#summaries[@]} -eq 0 ]; then
  emit "## bpftool aggregate"
  emit ""
  emit "_No per-shard summary JSON sidecars found under \`$IN_DIR\`._"
  if [ -n "$OUT_JSON" ]; then
    printf '{"shards":0,"suites":[]}\n' > "$OUT_JSON"
  fi
  exit 0
fi

MERGED_JSON=$(jq -s '
  {
    shards: length,
    per_shard: map({
      shard: .shard,
      snapshots: .snapshots,
      window: .window,
      peak: .peak
    }),
    suites: (
      [.[] | .shard as $sh | .suites[]? | . + {shard: $sh}]
      | group_by(.name)
      | map(
          sort_by(-.peak_bytes) as $by_peak
          | {
              name: $by_peak[0].name,
              peak_bytes: $by_peak[0].peak_bytes,
              peak_shard: $by_peak[0].shard,
              peak_duration_s: $by_peak[0].duration_s,
              peak_snapshots_in_window: $by_peak[0].snapshots_in_window,
              peak_series: $by_peak[0].series,
              peak_result: $by_peak[0].result
            }
        )
      | sort_by(-.peak_bytes)
    ),
    peak_maps: (
      [.[] | .peak.maps_grouped[]?]
      | group_by(.name)
      | map({
          name: .[0].name,
          type: .[0].type,
          max_total_memlock: ([.[].total_memlock] | max),
          max_count: ([.[].count] | max),
          max_entries: ([.[].max_entries] | max),
          observed_in_shards: length
        })
      | sort_by(-.max_total_memlock)
    ),
    peak_progs: (
      [.[] | .peak.progs_grouped[]?]
      | group_by(.name)
      | map({
          name: .[0].name,
          type: .[0].type,
          max_total_run_time_ns: ([.[].total_run_time_ns] | max),
          max_total_run_cnt: ([.[].total_run_cnt] | max),
          observed_in_shards: length
        })
      | sort_by(-.max_total_run_time_ns)
    )
  }
' "${summaries[@]}")

emit "## bpftool aggregate"
emit ""
emit "_Data source: \`bpftool map show -j\` + \`bpftool prog show -j\`, sampled across all integration test shards._"
emit "_Future data sources for this section may include bpftop and OBI's own internal metrics._"
emit ""

shard_count=$(jq -r '.shards' <<< "$MERGED_JSON")
total_suites=$(jq -r '.suites | length' <<< "$MERGED_JSON")

emit "**Run overview**"
emit ""
emit "| metric | value |"
emit "| --- | ---: |"
emit "| shards reporting | $shard_count |"
emit "| suites observed | $total_suites |"
emit ""

emit "**Per-shard peaks**"
emit ""
emit "| shard | peak memlock (MiB) | maps at peak | progs at peak |"
emit "| --- | ---: | ---: | ---: |"

while IFS= read -r line; do emit "$line"; done < <(jq -r '
  .per_shard
  | sort_by(.shard)
  | .[]
  | "| \(.shard) | \((.peak.total_bytes_memlock / 1024 / 1024 * 100 | round / 100)) | \(.peak.maps) | \(.peak.progs) |"
' <<< "$MERGED_JSON")
emit ""

# Sparkline helper, identical to the one in summary.sh.
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

if [ "$total_suites" -gt 0 ]; then
  emit "### Top suites by peak memlock (across all shards)"
  emit ""
  emit "Each suite only runs on one shard. \`peak shard\` is where it ran. \`trend\` is the in-shard sampler series for that suite."
  emit ""
  emit "| suite | duration (s) | peak memlock (MiB) | peak shard | trend |"
  emit "| --- | ---: | ---: | --- | --- |"

  rows=$(jq -r '
    .suites
    | .[0:30]
    | .[]
    | [
        .name,
        (.peak_duration_s // 0),
        (.peak_bytes / 1024 / 1024 * 100 | round / 100),
        .peak_shard,
        (.peak_series | tojson)
      ] | @tsv
  ' <<< "$MERGED_JSON")

  while IFS=$'\t' read -r name duration_s peak_mib shard series; do
    spark=$(sparkline_from_json <<< "$series")
    emit "| \`$name\` | $duration_s | $peak_mib | $shard | $spark |"
  done <<< "$rows"
  emit ""
fi

# Cross-shard top-N maps & progs: max value per name across all shards' peaks.
peak_map_count=$(jq -r '.peak_maps | length' <<< "$MERGED_JSON")
if [ "$peak_map_count" -gt 0 ]; then
  emit "<details><summary>Top 20 maps at peak (max across all shards)</summary>"
  emit ""
  emit "_Per-name max of the \`total bytes_memlock\` observed in any shard's peak snapshot. \`observed in N shards\` indicates how many shards saw the map at all._"
  emit ""
  emit "| name | type | max total bytes_memlock (MiB) | max instances per shard | max_entries | observed in N shards |"
  emit "| --- | --- | ---: | ---: | ---: | ---: |"

  while IFS= read -r line; do emit "$line"; done < <(jq -r '
    .peak_maps
    | .[0:20]
    | .[]
    | "| \(.name) | \(.type) | \((.max_total_memlock / 1024 / 1024 * 100 | round / 100)) | \(.max_count) | \(.max_entries) | \(.observed_in_shards) |"
  ' <<< "$MERGED_JSON")

  emit ""
  emit "</details>"
  emit ""
fi

peak_prog_count=$(jq -r '.peak_progs | length' <<< "$MERGED_JSON")
if [ "$peak_prog_count" -gt 0 ]; then
  emit "<details><summary>Top 10 programs at peak (max run_time_ns across all shards)</summary>"
  emit ""
  emit "| name | type | max run_time_ns | max run_cnt | observed in N shards |"
  emit "| --- | --- | ---: | ---: | ---: |"

  while IFS= read -r line; do emit "$line"; done < <(jq -r '
    .peak_progs
    | .[0:10]
    | .[]
    | "| \(.name) | \(.type) | \(.max_total_run_time_ns) | \(.max_total_run_cnt) | \(.observed_in_shards) |"
  ' <<< "$MERGED_JSON")

  emit ""
  emit "</details>"
  emit ""
fi

emit "<details><summary>How to interpret this report</summary>"
emit ""
emit "- **memlock** is the bytes the kernel locks on behalf of an eBPF map (\`bpftool map show -j\` → \`bytes_memlock\`). It tracks closely with map sizing in the source."
emit "- **Map names** are truncated to 15 characters by the kernel's \`BPF_OBJ_NAME_LEN\`."
emit "- **Per-suite attribution** intersects the per-shard sampler timeline with gotestsum's test-event log. Snapshots that fall inside a top-level test's run-to-pass window are attributed to that suite. Peak values include any concurrent residue from prior tests whose teardown is still in flight, so treat absolute numbers as upper bounds, not minimums."
emit "- **Trend** sparklines on the suite table show the in-shard sampler series during that suite's run window."
emit ""
emit "</details>"

if [ -n "$OUT_JSON" ]; then
  printf '%s\n' "$MERGED_JSON" > "$OUT_JSON"
fi
