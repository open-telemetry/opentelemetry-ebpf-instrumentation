#!/usr/bin/env bash
# PoC: aggregate per-shard bpftool snapshot directories into one summary.
#
# Expects an input dir containing one subdirectory per shard, each holding
# snap-*.json files (as produced by bpf-metrics-sampler.sh). The standard
# layout from actions/download-artifact with no `name:` filter is:
#   <in_dir>/bpf-metrics-<shard_id>-<run>/snap-*.json
#
# Emits markdown to $GITHUB_STEP_SUMMARY (or stdout) and writes a copy to
# <out_file> for upload as a workflow-level artifact.
#
# Usage: ./scripts/bpf-metrics-aggregate.sh <in_dir> <out_file>
#
# NOTE: This sums bytes_memlock across ALL eBPF objects on the runner, not
# just OBI's. See bpf-metrics-summary.sh for the same caveat.
set -euo pipefail

IN_DIR="${1:-./all-shards}"
OUT_FILE="${2:-/tmp/bpf-metrics-aggregate.md}"

: > "$OUT_FILE"

emit() {
  printf '%s\n' "$1" >> "$OUT_FILE"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

shopt -s nullglob
shard_dirs=("$IN_DIR"/bpf-metrics-*)

if [ ${#shard_dirs[@]} -eq 0 ]; then
  emit "## eBPF metrics (aggregate)"
  emit ""
  emit "_No per-shard artifacts found under \`$IN_DIR\`._"
  exit 0
fi

emit "## eBPF metrics — aggregate across ${#shard_dirs[@]} shards"
emit ""
emit "| shard | snapshots | peak memlock (bytes) | peak memlock (MiB) | maps@peak | progs@peak |"
emit "| --- | ---: | ---: | ---: | ---: | ---: |"

best_total=-1
best_shard=""
best_snapshot=""

for shard_dir in "${shard_dirs[@]}"; do
  shard_name=$(basename "$shard_dir")
  # Strip the bpf-metrics- prefix and the trailing -<run> suffix for display.
  shard_label=${shard_name#bpf-metrics-}
  shard_label=${shard_label%-*}

  snapshots=("$shard_dir"/snap-*.json)
  if [ ${#snapshots[@]} -eq 0 ]; then
    emit "| $shard_label | 0 | n/a | n/a | n/a | n/a |"
    continue
  fi

  shard_peak_snap=""
  shard_peak_total=-1
  for f in "${snapshots[@]}"; do
    total=$(jq '[.maps[]?.bytes_memlock // 0] | add // 0' "$f" 2>/dev/null || echo 0)
    if [ "$total" -gt "$shard_peak_total" ]; then
      shard_peak_total=$total
      shard_peak_snap=$f
    fi
  done

  maps_at_peak=$(jq '.maps | length' "$shard_peak_snap")
  progs_at_peak=$(jq '.progs | length' "$shard_peak_snap")
  mib=$(awk -v t="$shard_peak_total" 'BEGIN{printf "%.2f", t/1024/1024}')

  emit "| $shard_label | ${#snapshots[@]} | $shard_peak_total | $mib | $maps_at_peak | $progs_at_peak |"

  if [ "$shard_peak_total" -gt "$best_total" ]; then
    best_total=$shard_peak_total
    best_shard=$shard_label
    best_snapshot=$shard_peak_snap
  fi
done

emit ""

if [ -z "$best_snapshot" ]; then
  emit "_No snapshots contained map data._"
  exit 0
fi

best_mib=$(awk -v t="$best_total" 'BEGIN{printf "%.2f", t/1024/1024}')
emit "### Overall peak: shard \`$best_shard\` — **$best_total** bytes ($best_mib MiB)"
emit ""
emit "Snapshot: \`$(basename "$best_snapshot")\` from \`$best_shard\`"
emit ""
emit "#### Top 20 maps by \`bytes_memlock\` at overall peak"
emit ""
emit "| name | type | max_entries | bytes_memlock |"
emit "| --- | --- | ---: | ---: |"

while IFS= read -r line; do emit "$line"; done < <(jq -r '
  .maps
  | map({
      name: (.name // "<unnamed>"),
      type: (.type // "?"),
      max_entries: (.max_entries // 0),
      bytes_memlock: (.bytes_memlock // 0)
    })
  | sort_by(-.bytes_memlock)
  | .[0:20]
  | .[]
  | "| \(.name) | \(.type) | \(.max_entries) | \(.bytes_memlock) |"
' "$best_snapshot")

emit ""
emit "#### Top 10 programs by \`run_time_ns\` at overall peak"
emit ""
emit "| name | type | run_cnt | run_time_ns |"
emit "| --- | --- | ---: | ---: |"

while IFS= read -r line; do emit "$line"; done < <(jq -r '
  .progs
  | map({
      name: (.name // "<unnamed>"),
      type: (.type // "?"),
      run_cnt: (.run_cnt // 0),
      run_time_ns: (.run_time_ns // 0)
    })
  | sort_by(-.run_time_ns)
  | .[0:10]
  | .[]
  | "| \(.name) | \(.type) | \(.run_cnt) | \(.run_time_ns) |"
' "$best_snapshot")
