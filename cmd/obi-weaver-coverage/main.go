// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-weaver-coverage aggregates the per-suite weaver live-check reports
// produced across the sharded test matrix into a single telemetry coverage
// verdict. The declared signals are resolved from the OBI schema itself
// (weaver registry resolve --v2): every metric and span definition with its
// declared attributes. The observed set is the union, across every report, of
// the signals live-check matched samples to and the attribute keys seen on the
// samples of each signal. Every declared item no suite observed is a gap.
//
// All of the aggregation logic lives here rather than in the workflow: the CI
// job is `make weaver-coverage`, nothing more.
//
// Usage:
//
//	obi-weaver-coverage --schema <dir> --oci-bin docker --weaver-image <img> --in <dir> [--out-json f] [--fail-on-gap]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func writeJSON(res Result, outJSON string) {
	if outJSON == "" {
		return
	}
	j, err := json.MarshalIndent(res, "", "  ")
	if err == nil {
		err = os.WriteFile(outJSON, append(j, '\n'), 0o644)
	}
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func main() {
	in := flag.String("in", "", "directory searched recursively for weaver-report-*.json")
	schema := flag.String("schema", "", "OBI registry path; resolved via weaver to derive the declared signals")
	ociBin := flag.String("oci-bin", "docker", "container runtime used to run the weaver image")
	weaverImage := flag.String("weaver-image", "", "pinned weaver image used to resolve the schema")
	outJSON := flag.String("out-json", "", "write the result JSON to this file")
	failOnGap := flag.Bool("fail-on-gap", false, "exit non-zero when a signal definition was never observed")
	flag.Parse()

	if *schema == "" || *weaverImage == "" {
		fatal("--schema and --weaver-image are required")
	}
	resolved, err := resolveSchema(*ociBin, *weaverImage, *schema)
	if err != nil {
		fatal(err.Error())
	}
	signals, err := parseSignals(resolved)
	if err != nil {
		fatal(err.Error())
	}

	reports, err := LoadReports(*in)
	if err != nil {
		fatal(err.Error())
	}
	if len(reports) == 0 {
		fmt.Printf("## Weaver telemetry coverage\n\n_No weaver reports (`weaver-report-*.json`) found under `%s`._\n", *in)
		writeJSON(Aggregate(signals, nil), *outJSON)
		if *failOnGap {
			os.Exit(1)
		}
		return
	}

	res := Aggregate(signals, reports)
	fmt.Print(res.Markdown())
	writeJSON(res, *outJSON)

	if n := res.FailingGaps(); n > 0 && *failOnGap {
		fmt.Fprintf(os.Stderr, "weaver telemetry coverage: %d failing gap(s)\n", n)
		os.Exit(1)
	}
}
