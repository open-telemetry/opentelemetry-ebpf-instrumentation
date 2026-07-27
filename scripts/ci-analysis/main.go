// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// ci-analysis parses gotestsum JSON reports and Docker log artifacts from
// GitHub Actions and generates Markdown CI reliability reports.
//
// Subcommands:
//
//	daily   Analyze the last few days of CI runs (run nightly).
//	weekly  Roll up daily snapshots into a weekly report (run Mondays).
//
// Each subcommand can also persist a JSON snapshot for downstream rollups
// (daily → weekly → monthly).
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usageAndExit()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "daily":
		runDaily(args)
	case "weekly":
		runWeekly(args)
	case "-h", "--help", "help":
		usageAndExit()
	default:
		log.Printf("unknown subcommand: %q", cmd)
		usageAndExit()
	}
}

func usageAndExit() {
	fmt.Fprint(os.Stderr, `Usage: ci-analysis <subcommand> [flags]

Subcommands:
  daily    Analyze recent CI runs from downloaded artifacts
  weekly   Roll up daily snapshots into a weekly report

Run "ci-analysis <subcommand> -h" for subcommand flags.
`)
	os.Exit(2)
}
