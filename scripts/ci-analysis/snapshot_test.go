// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSnapshotRoundTrip(t *testing.T) {
	snap := Snapshot{
		Version:     snapshotVersion,
		Kind:        snapshotKindDaily,
		GeneratedAt: "2026-05-05T06:00:00Z",
		PeriodStart: "2026-05-01",
		PeriodEnd:   "2026-05-05",
		Runs: []RunMeta{
			{RunID: "1", CreatedAt: "2026-05-01T00:00:00Z", Workflow: "wf-A", Conclusion: "success"},
		},
		Results: []TestResult{
			{RunID: "1", Workflow: "wf-A", Package: "pkg/x", Test: "TestX", Outcome: "passed"},
		},
	}

	path := filepath.Join(t.TempDir(), "snapshot.json")
	require.NoError(t, writeSnapshot(path, snap))

	got, err := readSnapshot(path)
	require.NoError(t, err)
	require.Equal(t, snap, got)
}

func TestMergeSnapshotsDeduplicates(t *testing.T) {
	// Two snapshots with overlapping runs and results.
	// Dedup keys: run_id for runs, (run_id, package, test) for results.
	// Run 2 appears in both snapshots and must collapse to one.
	snapA := Snapshot{
		Runs: []RunMeta{
			{RunID: "1", CreatedAt: "2026-05-01T00:00:00Z", Workflow: "wf"},
			{RunID: "2", CreatedAt: "2026-05-02T00:00:00Z", Workflow: "wf"},
		},
		Results: []TestResult{
			{RunID: "1", Workflow: "wf", Package: "pkg", Test: "TestX", Outcome: "passed"},
			{RunID: "2", Workflow: "wf", Package: "pkg", Test: "TestX", Outcome: "failed"},
		},
	}
	snapB := Snapshot{
		Runs: []RunMeta{
			{RunID: "2", CreatedAt: "2026-05-02T00:00:00Z", Workflow: "wf"}, // duplicate
			{RunID: "3", CreatedAt: "2026-05-03T00:00:00Z", Workflow: "wf"},
		},
		Results: []TestResult{
			{RunID: "2", Workflow: "wf", Package: "pkg", Test: "TestX", Outcome: "failed"}, // duplicate
			{RunID: "3", Workflow: "wf", Package: "pkg", Test: "TestX", Outcome: "passed"},
		},
	}

	runs, results := mergeSnapshots([]Snapshot{snapA, snapB})
	require.Len(t, runs, 3)
	require.Len(t, results, 3)

	// Same test name in a different package must not merge.
	snapC := Snapshot{
		Results: []TestResult{
			{RunID: "1", Workflow: "wf", Package: "pkg/other", Test: "TestX", Outcome: "passed"},
		},
	}
	_, results = mergeSnapshots([]Snapshot{snapA, snapC})
	require.Len(t, results, 3) // pkg/TestX (run 1), pkg/TestX (run 2), pkg/other/TestX (run 1)
}

func TestFilterByDate(t *testing.T) {
	runs := []RunMeta{
		{RunID: "old", CreatedAt: "2026-04-20T00:00:00Z"},
		{RunID: "new", CreatedAt: "2026-05-04T00:00:00Z"},
	}
	results := []TestResult{
		{RunID: "old", Test: "TestX"},
		{RunID: "new", Test: "TestX"},
	}

	gotRuns, gotResults := filterByDate(runs, results, "2026-05-01")
	require.Len(t, gotRuns, 1)
	require.Equal(t, "new", gotRuns[0].RunID)
	require.Len(t, gotResults, 1)
	require.Equal(t, "new", gotResults[0].RunID)
}

func TestLoadSnapshotsRecursive(t *testing.T) {
	dir := t.TempDir()
	snap1 := Snapshot{Version: snapshotVersion, Kind: snapshotKindDaily, Runs: []RunMeta{{RunID: "1"}}}
	snap2 := Snapshot{Version: snapshotVersion, Kind: snapshotKindDaily, Runs: []RunMeta{{RunID: "2"}}}
	require.NoError(t, writeSnapshot(filepath.Join(dir, "run-1", "snapshot.json"), snap1))
	require.NoError(t, writeSnapshot(filepath.Join(dir, "run-2", "snapshot.json"), snap2))

	snaps, err := loadSnapshots(dir)
	require.NoError(t, err)
	require.Len(t, snaps, 2)
}

func TestValidateSince(t *testing.T) {
	t.Run("date-only", func(t *testing.T) {
		require.NoError(t, validateSince("2026-05-18"))
	})
	t.Run("rfc3339", func(t *testing.T) {
		require.NoError(t, validateSince("2026-05-18T06:00:00Z"))
	})
	t.Run("garbage", func(t *testing.T) {
		err := validateSince("last-monday")
		require.Error(t, err)
		require.Contains(t, err.Error(), "YYYY-MM-DD or RFC3339")
	})
	t.Run("nearly-valid", func(t *testing.T) {
		require.Error(t, validateSince("2026/05/18"))
	})
}

func TestReadSnapshotRejectsFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version": 999, "kind": "daily"}`), 0o644))

	_, err := readSnapshot(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "newer than supported")
}
