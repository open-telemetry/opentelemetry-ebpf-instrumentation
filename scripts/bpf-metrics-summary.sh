#!/usr/bin/env bash
# PoC: read snapshots produced by bpf-metrics-sampler.sh and emit a markdown
# summary to stdout (or to $GITHUB_STEP_SUMMARY if set).
#
# NOTE: This sums bytes_memlock across ALL eBPF objects on the runner, not
# just OBI's. On a GH Actions runner this is a fair proxy because no other
# eBPF programs are loaded, but for production tracking we would filter
# by the OBI process PID via `bpftool prog show -j` -> `.pids[].pid`.
set -euo pipefail

IN_DIR="${1:-/tmp/bpfsamples}"

shopt -s nullglob
# Bash globs expand in lexically sorted order, which matches numerical
# order here since snap-*.json filenames embed a fixed-width unix timestamp.
snapshots=("$IN_DIR"/snap-*.json)

if [ ${#snapshots[@]} -eq 0 ]; then
  echo "No snapshots found in $IN_DIR" >&2
  exit 0
fi

emit() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  else
    printf '%s\n' "$1"
  fi
}

# Find the snapshot with the highest total bytes_memlock.
peak_snapshot=""
peak_total=-1
for f in "${snapshots[@]}"; do
  total=$(jq '[.maps[]?.bytes_memlock // 0] | add // 0' "$f" 2>/dev/null || echo 0)
  if [ "$total" -gt "$peak_total" ]; then
    peak_total=$total
    peak_snapshot=$f
  fi
done

first_snapshot=${snapshots[0]}
last_snapshot=${snapshots[-1]}
sample_count=${#snapshots[@]}

peak_map_count=$(jq '.maps | length' "$peak_snapshot")
peak_prog_count=$(jq '.progs | length' "$peak_snapshot")
peak_ts=$(jq -r '.ts' "$peak_snapshot")
first_ts=$(jq -r '.ts' "$first_snapshot")
last_ts=$(jq -r '.ts' "$last_snapshot")
peak_mib=$(awk -v t="$peak_total" 'BEGIN{printf "%.2f", t/1024/1024}')

emit "## eBPF metrics (PoC)"
emit ""
emit "- Snapshots taken: **$sample_count**"
emit "- Window: $first_ts → $last_ts (unix)"
emit "- Peak snapshot @ ts=$peak_ts"
emit "  - Total \`bytes_memlock\`: **$peak_total** bytes ($peak_mib MiB)"
emit "  - Maps loaded: $peak_map_count"
emit "  - Programs loaded: $peak_prog_count"
emit ""
emit "### Top 20 maps by \`bytes_memlock\` at peak"
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
' "$peak_snapshot")

emit ""
emit "### Top 10 programs by \`run_time_ns\` at peak"
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
' "$peak_snapshot")
