// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"log"
	"os"
	"time"
)

func runDaily(args []string) {
	fs := flag.NewFlagSet("daily", flag.ExitOnError)
	reportsDir := fs.String("reports-dir", "", "Directory containing gotestsum JSON report files (recursive)")
	logsDir := fs.String("logs-dir", "", "Directory containing Docker log files for failed runs (recursive)")
	metaFile := fs.String("meta", "", "JSON file with array of run metadata objects")
	repo := fs.String("repo", "open-telemetry/opentelemetry-ebpf-instrumentation", "GitHub repository for linking")
	snapshotOut := fs.String("snapshot-out", "", "Optional path to write a JSON snapshot for downstream rollups")
	// ExitOnError handles parse failures internally — no need to check the return.
	_ = fs.Parse(args)

	if *reportsDir == "" {
		log.Fatal("--reports-dir is required")
	}

	metaMap, err := loadRunMeta(*metaFile)
	if err != nil {
		log.Fatalf("loading metadata: %v", err)
	}

	results, err := parseAllReports(*reportsDir, *logsDir, metaMap)
	if err != nil {
		log.Fatalf("parsing reports: %v", err)
	}

	if err := writeReport(os.Stdout, "CI Test Analysis Report", results, metaMap, *repo); err != nil {
		log.Fatalf("writing report: %v", err)
	}

	if *snapshotOut != "" {
		minDate, maxDate := dateRangeFromMeta(metaMap)
		runs := make([]RunMeta, 0, len(metaMap))
		for _, rm := range metaMap {
			runs = append(runs, rm)
		}
		snap := Snapshot{
			Version:     snapshotVersion,
			Kind:        snapshotKindDaily,
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
