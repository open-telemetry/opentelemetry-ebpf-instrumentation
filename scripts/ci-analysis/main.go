// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// ci-analysis parses gotestsum JSON reports and Docker log artifacts from
// GitHub Actions, then generates a Markdown flaky-test analysis report.
//
// Usage:
//
//	go run ./scripts/ci-analysis [flags]
//	  --reports-dir  Directory containing gotestsum JSON report files (recursive)
//	  --logs-dir     Directory containing Docker log files for failed runs (recursive)
//	  --meta         JSON file with run metadata
//	  --repo         GitHub repository for linking (default: open-telemetry/opentelemetry-ebpf-instrumentation)
package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	reportsDir := flag.String("reports-dir", "", "Directory containing gotestsum JSON report files (recursive)")
	logsDir := flag.String("logs-dir", "", "Directory containing Docker log files for failed runs (recursive)")
	metaFile := flag.String("meta", "", "JSON file with array of run metadata objects")
	repo := flag.String("repo", "open-telemetry/opentelemetry-ebpf-instrumentation", "GitHub repository for linking")
	flag.Parse()

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

	if err := writeReport(os.Stdout, results, metaMap, *repo); err != nil {
		log.Fatalf("writing report: %v", err)
	}
}
