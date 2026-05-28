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
      | map({
          name: .[0].name,
          observations: length,
          peak_bytes: ([.[].peak_bytes] | max),
          peak_shard: (sort_by(-.peak_bytes) | .[0].shard),
          total_snapshots_in_window: ([.[].snapshots_in_window] | add),
          per_shard: map({
            shard: .shard,
            peak_bytes: .peak_bytes,
            snapshots_in_window: .snapshots_in_window,
            series: .series
          })
        })
      | sort_by(-.peak_bytes)
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
  emit "Sparkline shows the per-shard peak series for the suite, ordered by shard."
  emit ""
  emit "| suite | peak memlock (MiB) | peak shard | shards seen | trend across shards |"
  emit "| --- | ---: | --- | ---: | --- |"

  rows=$(jq -r '
    .suites
    | .[0:30]
    | .[]
    | [
        .name,
        (.peak_bytes / 1024 / 1024 * 100 | round / 100),
        .peak_shard,
        .observations,
        ([.per_shard | sort_by(.shard) | .[] | .peak_bytes] | tojson)
      ] | @tsv
  ' <<< "$MERGED_JSON")

  while IFS=$'\t' read -r name peak_mib shard observations series; do
    spark=$(sparkline_from_json <<< "$series")
    emit "| \`$name\` | $peak_mib | $shard | $observations | $spark |"
  done <<< "$rows"
  emit ""
fi

emit "<details><summary>How to interpret this report</summary>"
emit ""
emit "- **memlock** is the bytes the kernel locks on behalf of an eBPF map (\`bpftool map show -j\` → \`bytes_memlock\`). It tracks closely with map sizing in the source."
emit "- **Map names** are truncated to 15 characters by the kernel's \`BPF_OBJ_NAME_LEN\`."
emit "- **Per-suite attribution** intersects the per-shard sampler timeline with gotestsum's test-event log. Snapshots that fall inside a top-level test's run-to-pass window are attributed to that suite. Peak values include any concurrent residue from prior tests whose teardown is still in flight, so treat absolute numbers as upper bounds, not minimums."
emit "- **Trend** sparklines encode the per-shard peak series for that suite, ordered by shard label, using 8 unicode block heights."
emit ""
emit "</details>"

if [ -n "$OUT_JSON" ]; then
  printf '%s\n' "$MERGED_JSON" > "$OUT_JSON"
fi
