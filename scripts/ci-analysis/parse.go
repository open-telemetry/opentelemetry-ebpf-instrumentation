// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TestEvent represents a single go test -json event.
type TestEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

// TestResult is the parsed outcome for a single test in a single run.
// JSON tags define the on-disk snapshot schema consumed by the weekly
// rollup (see snapshot.go); changing them is a breaking change.
type TestResult struct {
	RunID    string `json:"run_id"`
	Workflow string `json:"workflow"`
	// Package is part of the test identity: unit-test shards run multiple Go
	// packages in one gotestsum file, so two TestFoo entries in different
	// packages must not be merged. Do not remove.
	Package          string `json:"package"`
	Test             string `json:"test"`
	Outcome          string `json:"outcome"`
	ErrorFingerprint string `json:"error_fingerprint,omitempty"`
	ErrorSnippet     string `json:"error_snippet,omitempty"`
}

// RunMeta contains metadata for each run being parsed.
type RunMeta struct {
	RunID      string `json:"run_id"`
	CreatedAt  string `json:"created_at"`
	Workflow   string `json:"workflow"`
	Conclusion string `json:"conclusion"`
}

func loadRunMeta(path string) (map[string]RunMeta, error) {
	m := map[string]RunMeta{}
	if path == "" {
		return m, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var metas []RunMeta
	if err := json.Unmarshal(data, &metas); err != nil {
		return nil, err
	}
	for _, rm := range metas {
		m[rm.RunID] = rm
	}
	return m, nil
}

func parseAllReports(reportsDir, logsDir string, metaMap map[string]RunMeta) ([]TestResult, error) {
	var all []TestResult

	err := filepath.WalkDir(reportsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".log") {
			return nil
		}

		relPath, _ := filepath.Rel(reportsDir, path)
		parts := strings.SplitN(relPath, string(filepath.Separator), 2)

		var runID string
		if len(parts) >= 1 {
			runID = parts[0]
		}

		meta := metaMap[runID]
		if meta.RunID == "" {
			meta.RunID = runID
		}

		f, err := os.Open(path)
		if err != nil {
			log.Printf("warning: opening %s: %v", path, err)
			return nil
		}
		defer f.Close()

		results, err := parseGotestsum(f, meta)
		if err != nil {
			log.Printf("warning: parsing %s: %v", path, err)
			return nil
		}

		if logsDir != "" {
			enrichWithDockerLogs(results, filepath.Join(logsDir, runID))
		}

		all = append(all, results...)
		return nil
	})

	return all, err
}

// testState tracks events for a single test across potential reruns.
type testState struct {
	outcomes   []string
	outputBuf  []string
	failOutput []string
}

// pkgTest identifies a test by both package and name; a gotestsum file can
// span multiple Go packages (unit-test shards), and tests sharing a name
// across packages must stay distinct.
type pkgTest struct{ pkg, test string }

func parseGotestsum(r io.Reader, meta RunMeta) ([]TestResult, error) {
	tests := map[pkgTest]*testState{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var ev TestEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Test == "" {
			continue
		}

		topTest := ev.Test
		if idx := strings.Index(ev.Test, "/"); idx > 0 {
			topTest = ev.Test[:idx]
		}

		key := pkgTest{ev.Package, topTest}
		ts, ok := tests[key]
		if !ok {
			ts = &testState{}
			tests[key] = ts
		}

		switch ev.Action {
		case "output":
			ts.outputBuf = append(ts.outputBuf, ev.Output)
		case "pass", "fail", "skip":
			if ev.Test == topTest {
				ts.outcomes = append(ts.outcomes, ev.Action)
				if ev.Action == "fail" {
					ts.failOutput = make([]string, len(ts.outputBuf))
					copy(ts.failOutput, ts.outputBuf)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning: %w", err)
	}

	var results []TestResult
	for key, ts := range tests {
		r := TestResult{
			RunID:    meta.RunID,
			Workflow: meta.Workflow,
			Package:  key.pkg,
			Test:     key.test,
			Outcome:  classifyOutcome(ts.outcomes),
		}
		if r.Outcome == "failed" || r.Outcome == "flaky-passed" {
			r.ErrorSnippet = extractErrorSnippet(ts.failOutput)
			errorMsg, traceSite := extractErrorBlock(ts.failOutput)
			r.ErrorFingerprint = fingerprintFromTestOutput(errorMsg, r.ErrorSnippet, traceSite)
		}
		results = append(results, r)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Test != results[j].Test {
			return results[i].Test < results[j].Test
		}
		return results[i].Package < results[j].Package
	})
	return results, nil
}

func classifyOutcome(outcomes []string) string {
	if len(outcomes) == 0 {
		return "unknown"
	}
	var hasFail, hasPass bool
	for _, o := range outcomes {
		switch o {
		case "fail":
			hasFail = true
		case "pass":
			hasPass = true
		case "skip":
			if !hasFail && !hasPass {
				return "skipped"
			}
		}
	}
	switch {
	case hasFail && hasPass:
		return "flaky-passed"
	case hasFail:
		return "failed"
	case hasPass:
		return "passed"
	default:
		return "skipped"
	}
}

func extractErrorSnippet(output []string) string {
	var snippet strings.Builder
	for _, line := range output {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if snippetRE.MatchString(line) && snippet.Len() < maxSnippetLen {
			snippet.WriteString(trimmed)
			snippet.WriteString("\n")
		}
	}
	s := strings.TrimSpace(snippet.String())

	// Fallback: last 10 non-empty lines when no pattern matched.
	if s == "" {
		var lines []string
		for i := len(output) - 1; i >= 0 && len(lines) < 10; i-- {
			if t := strings.TrimSpace(output[i]); t != "" {
				lines = append(lines, t)
			}
		}
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
		s = strings.Join(lines, "\n")
	}

	if len(s) > maxSnippetLen {
		return s[:maxSnippetLen]
	}
	return s
}
