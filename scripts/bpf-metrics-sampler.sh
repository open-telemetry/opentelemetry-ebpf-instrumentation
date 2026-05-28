#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# PoC: poll bpftool periodically and append JSON snapshots to an output dir.
# Each snapshot is one file: <out_dir>/snap-<unix_ts>.json with shape:
#   { "ts": <unix>, "maps": [...], "progs": [...] }
#
# Intended to be run in the background while an integration test executes:
#   ./scripts/bpf-metrics-sampler.sh /tmp/bpfsamples 2 &
#   SAMPLER_PID=$!
#   ... run test ...
#   kill "$SAMPLER_PID" || true
#
# Caveats:
# - Filenames embed a 1-second resolution timestamp; intervals < 1s would
#   cause snapshot collisions. The default is 2s.
# - INTERVAL is passed to `sleep` verbatim; validate before invoking.
# - Captures ALL eBPF objects on the runner, not just OBI's. Acceptable for
#   GH Actions runners where nothing else loads eBPF; for a richer signal,
#   filter by PID using `.pids[].pid` from `bpftool prog show -j`.
set -euo pipefail

OUT_DIR="${1:-/tmp/bpfsamples}"
INTERVAL="${2:-2}"

if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ]; then
  echo "INTERVAL must be a positive integer (seconds), got: $INTERVAL" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

# bpftool typically needs root; on GH runners passwordless sudo is fine.
BPFTOOL=(sudo bpftool)

# Enable BPF stats (run_time_ns / run_cnt) for the duration of the sampler.
# Best-effort: requires CAP_SYS_ADMIN and may be a no-op on locked-down hosts.
sudo sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1 || true

# EXIT trap restores the sysctl on SIGTERM (the default `kill`). It does NOT
# fire on SIGKILL — acceptable because GH runners are torn down after the job.
cleanup() {
  sudo sysctl -w kernel.bpf_stats_enabled=0 >/dev/null 2>&1 || true
}
trap cleanup EXIT

while true; do
  ts=$(date +%s)
  # Both queries are best-effort; emit empty arrays on failure so the
  # downstream scripts can still parse the file.
  maps=$("${BPFTOOL[@]}" map show -j 2>/dev/null || echo '[]')
  progs=$("${BPFTOOL[@]}" prog show -j 2>/dev/null || echo '[]')
  # Write to a temp file then rename so readers never observe a partial
  # snapshot, even if we get SIGTERM'd mid-write.
  tmp="$OUT_DIR/.snap-$ts.json.tmp"
  printf '{"ts":%s,"maps":%s,"progs":%s}\n' "$ts" "$maps" "$progs" > "$tmp"
  mv "$tmp" "$OUT_DIR/snap-$ts.json"
  sleep "$INTERVAL"
done
