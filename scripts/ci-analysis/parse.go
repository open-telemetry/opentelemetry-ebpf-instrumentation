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
	"regexp"
	"sort"
	"strings"
)

// TestEvent represents a single go test -json event.
type TestEvent struct {
	Time    string  `json:"Time"`
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Output  string  `json:"Output"`
	Elapsed float64 `json:"Elapsed"`
}

// TestResult is the parsed outcome for a single test in a single run.
type TestResult struct {
	RunID            string  `json:"run_id"`
	SHA              string  `json:"sha"`
	CreatedAt        string  `json:"created_at"`
	Workflow         string  `json:"workflow"`
	Shard            string  `json:"shard"`
	Test             string  `json:"test"`
	Package          string  `json:"package"`
	Outcome          string  `json:"outcome"`
	Attempts         int     `json:"attempts"`
	ElapsedS         float64 `json:"elapsed_s"`
	ErrorFingerprint string  `json:"error_fingerprint,omitempty"`
	ErrorSnippet     string  `json:"error_snippet,omitempty"`
}

// RunMeta contains metadata for each run being parsed.
type RunMeta struct {
	RunID      string `json:"run_id"`
	SHA        string `json:"sha"`
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
		parts := strings.SplitN(relPath, string(filepath.Separator), 3)

		var runID, shard string
		if len(parts) >= 2 {
			runID = parts[0]
			shard = extractShard(parts[1])
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

		results, err := parseGotestsum(f, meta, shard)
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

var shardRE = regexp.MustCompile(`reports?-(\d+)-`)

func extractShard(artifactName string) string {
	m := shardRE.FindStringSubmatch(artifactName)
	if len(m) >= 2 {
		return "shard-" + m[1]
	}
	return artifactName
}

// testState tracks events for a single test across potential reruns.
type testState struct {
	pkg        string
	outcomes   []string
	elapsed    float64
	outputBuf  []string
	failOutput []string
}

func parseGotestsum(r io.Reader, meta RunMeta, shard string) ([]TestResult, error) {
	tests := map[string]*testState{}
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

		ts, ok := tests[topTest]
		if !ok {
			ts = &testState{pkg: ev.Package}
			tests[topTest] = ts
		}

		switch ev.Action {
		case "output":
			ts.outputBuf = append(ts.outputBuf, ev.Output)
		case "pass", "fail", "skip":
			if ev.Test == topTest {
				ts.outcomes = append(ts.outcomes, ev.Action)
				ts.elapsed = ev.Elapsed
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
	for testName, ts := range tests {
		r := TestResult{
			RunID:     meta.RunID,
			SHA:       meta.SHA,
			CreatedAt: meta.CreatedAt,
			Workflow:  meta.Workflow,
			Shard:     shard,
			Test:      testName,
			Package:   ts.pkg,
			Outcome:   classifyOutcome(ts.outcomes),
			Attempts:  countAttempts(ts.outcomes),
			ElapsedS:  ts.elapsed,
		}
		if r.Outcome == "failed" || r.Outcome == "flaky-passed" {
			r.ErrorSnippet = extractErrorSnippet(ts.failOutput)
			r.ErrorFingerprint = fingerprintFromTestOutput(r.ErrorSnippet)
		}
		results = append(results, r)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Test < results[j].Test
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

func countAttempts(outcomes []string) int {
	count := 0
	for _, o := range outcomes {
		if o == "pass" || o == "fail" {
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
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
