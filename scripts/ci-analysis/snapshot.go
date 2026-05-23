// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// snapshotVersion is bumped when the on-disk schema changes incompatibly.
// Consumers refuse snapshots with a higher version than they know about.
const snapshotVersion = 1

// Snapshot kinds. Daily snapshots feed the weekly rollup; weekly snapshots
// will feed a future monthly rollup.
const (
	snapshotKindDaily  = "daily"
	snapshotKindWeekly = "weekly"
)

// Snapshot is the persisted output of an analysis run. It contains enough
// raw data for a downstream rollup to re-aggregate without re-fetching
// from GitHub — important because GitHub artifact retention is shorter
// than the rollup windows we want to report on.
type Snapshot struct {
	Version     int          `json:"version"`
	Kind        string       `json:"kind"`
	GeneratedAt string       `json:"generated_at"`
	PeriodStart string       `json:"period_start"`
	PeriodEnd   string       `json:"period_end"`
	Runs        []RunMeta    `json:"runs"`
	Results     []TestResult `json:"results"`
}

func writeSnapshot(path string, snap Snapshot) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating snapshot dir: %w", err)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling snapshot: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing snapshot: %w", err)
	}
	return nil
}

func readSnapshot(path string) (Snapshot, error) {
	var snap Snapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return snap, err
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		return snap, fmt.Errorf("parsing %s: %w", path, err)
	}
	if snap.Version > snapshotVersion {
		return snap, fmt.Errorf("%s: snapshot version %d is newer than supported version %d", path, snap.Version, snapshotVersion)
	}
	return snap, nil
}

// loadSnapshots walks dir and reads every *.json snapshot file beneath it.
// File names are not significant — only the contents matter.
func loadSnapshots(dir string) ([]Snapshot, error) {
	var snaps []Snapshot
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		s, err := readSnapshot(path)
		if err != nil {
			return err
		}
		snaps = append(snaps, s)
		return nil
	})
	return snaps, err
}

// mergeSnapshots combines runs and results across snapshots, deduplicating
// by run_id (for runs) and by (run_id, package, test) for results. Daily
// snapshots overlap when the source workflow uses a multi-day lookback
// window — the same run can appear in several daily snapshots — so dedup
// is required to keep the rollup arithmetic correct.
func mergeSnapshots(snaps []Snapshot) ([]RunMeta, []TestResult) {
	runMap := map[string]RunMeta{}
	type resultKey struct {
		runID string
		pkgTest
	}
	resultMap := map[resultKey]TestResult{}

	for _, s := range snaps {
		for _, rm := range s.Runs {
			if _, exists := runMap[rm.RunID]; !exists {
				runMap[rm.RunID] = rm
			}
		}
		for _, r := range s.Results {
			k := resultKey{r.RunID, pkgTest{r.Package, r.Test}}
			if _, exists := resultMap[k]; !exists {
				resultMap[k] = r
			}
		}
	}

	runs := make([]RunMeta, 0, len(runMap))
	for _, rm := range runMap {
		runs = append(runs, rm)
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].CreatedAt != runs[j].CreatedAt {
			return runs[i].CreatedAt < runs[j].CreatedAt
		}
		return runs[i].RunID < runs[j].RunID
	})

	results := make([]TestResult, 0, len(resultMap))
	for _, r := range resultMap {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].RunID != results[j].RunID {
			return results[i].RunID < results[j].RunID
		}
		if results[i].Package != results[j].Package {
			return results[i].Package < results[j].Package
		}
		return results[i].Test < results[j].Test
	})
	return runs, results
}

// validateSince checks that since parses as either YYYY-MM-DD or RFC3339.
// Both formats compare correctly under lexicographic ordering against the
// RFC3339 timestamps stored in RunMeta.CreatedAt, so no normalization is
// needed — only validation, to fail fast on typos rather than producing a
// silently-empty report.
func validateSince(since string) error {
	if _, err := time.Parse("2006-01-02", since); err == nil {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, since); err == nil {
		return nil
	}
	return fmt.Errorf("must be YYYY-MM-DD or RFC3339, got %q", since)
}

// filterByDate keeps runs whose CreatedAt is >= since, and the results that
// belong to those runs. since may be a date prefix (YYYY-MM-DD) or full
// RFC3339; both compare correctly under lexicographic ordering. Callers
// should call validateSince first to reject malformed input.
func filterByDate(runs []RunMeta, results []TestResult, since string) ([]RunMeta, []TestResult) {
	if since == "" {
		return runs, results
	}
	keepRun := map[string]bool{}
	filteredRuns := make([]RunMeta, 0, len(runs))
	for _, rm := range runs {
		if rm.CreatedAt >= since {
			keepRun[rm.RunID] = true
			filteredRuns = append(filteredRuns, rm)
		}
	}
	filteredResults := make([]TestResult, 0, len(results))
	for _, r := range results {
		if keepRun[r.RunID] {
			filteredResults = append(filteredResults, r)
		}
	}
	return filteredRuns, filteredResults
}
