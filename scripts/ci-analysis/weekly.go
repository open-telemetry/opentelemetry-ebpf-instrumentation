// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"log"
	"os"
	"time"
)

func runWeekly(args []string) {
	fs := flag.NewFlagSet("weekly", flag.ExitOnError)
	snapshotsDir := fs.String("snapshots-dir", "", "Directory containing daily snapshot JSON files (recursive)")
	since := fs.String("since", "", "Only include runs created on or after this date (YYYY-MM-DD or RFC3339); defaults to 7 days ago UTC")
	repo := fs.String("repo", "open-telemetry/opentelemetry-ebpf-instrumentation", "GitHub repository for linking")
	snapshotOut := fs.String("snapshot-out", "", "Optional path to write a JSON snapshot for downstream rollups (e.g. monthly)")
	title := fs.String("title", "Weekly CI Test Analysis Report", "Report title")
	// ExitOnError handles parse failures internally — no need to check the return.
	_ = fs.Parse(args)

	if *snapshotsDir == "" {
		log.Fatal("--snapshots-dir is required")
	}

	if *since == "" {
		*since = time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02")
	} else if err := validateSince(*since); err != nil {
		log.Fatalf("--since: %v", err)
	}

	snaps, err := loadSnapshots(*snapshotsDir)
	if err != nil {
		log.Fatalf("loading snapshots: %v", err)
	}
	if len(snaps) == 0 {
		log.Printf("warning: no snapshot files found in %s", *snapshotsDir)
	}

	runs, results := mergeSnapshots(snaps)
	runs, results = filterByDate(runs, results, *since)

	metaMap := make(map[string]RunMeta, len(runs))
	for _, rm := range runs {
		metaMap[rm.RunID] = rm
	}

	if err := writeReport(os.Stdout, *title, results, metaMap, *repo); err != nil {
		log.Fatalf("writing report: %v", err)
	}

	if *snapshotOut != "" {
		minDate, maxDate := dateRangeFromMeta(metaMap)
		snap := Snapshot{
			Version:     snapshotVersion,
			Kind:        snapshotKindWeekly,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			PeriodStart: minDate,
			PeriodEnd:   maxDate,
			Runs:        runs,
			Results:     results,
		}
		if err := writeSnapshot(*snapshotOut, snap); err != nil {
			log.Fatalf("writing snapshot: %v", err)
		}
	}
}
