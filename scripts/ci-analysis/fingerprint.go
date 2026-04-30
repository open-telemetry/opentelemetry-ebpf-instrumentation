// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxSnippetLen = 500

type logError struct {
	fingerprint string
	snippet     string
}

// errorPatterns is the ordered list of known CI failure patterns.
// Add new patterns here — they automatically extend fingerprinting
// and snippet extraction. First match wins.
var errorPatterns = []struct {
	regex       *regexp.Regexp
	fingerprint string
}{
	{regexp.MustCompile(`(?i)port is already allocated`), "port-conflict"},
	{regexp.MustCompile(`(?i)address already in use`), "port-conflict"},
	{regexp.MustCompile(`(?i)Bind for .+ failed`), "port-conflict"},
	{regexp.MustCompile(`(?i)DATA RACE`), "data-race"},
	{regexp.MustCompile(`(?i)context deadline exceeded`), "timeout"},
	{regexp.MustCompile(`(?i)test timed out after`), "timeout"},
	{regexp.MustCompile(`(?i)no space left on device`), "disk-full"},
	{regexp.MustCompile(`(?i)connection refused`), "connection-refused"},
	{regexp.MustCompile(`(?i)Error response from daemon`), "docker-error"},
	{regexp.MustCompile(`(?i)Cannot connect to the Docker daemon`), "docker-error"},
	{regexp.MustCompile(`(?i)OCI runtime create failed`), "docker-error"},
	{regexp.MustCompile(`(?i)panic:`), "panic"},
	{regexp.MustCompile(`(?i)signal: killed`), "oom-killed"},
	{regexp.MustCompile(`(?i)received signal: interrupt`), "cancelled"},
	{regexp.MustCompile(`(?i)exit status \d+`), "exit-error"},
}

// snippetRE matches lines worth including in error snippets: Go test
// output markers plus all fingerprint patterns (built automatically).
var snippetRE = func() *regexp.Regexp {
	parts := []string{`Error:`, `Error Trace:`, `FAIL`}
	for _, ep := range errorPatterns {
		parts = append(parts, ep.regex.String())
	}
	return regexp.MustCompile(strings.Join(parts, "|"))
}()

// errorTraceRE captures the file:line on the same line as a testify
// "Error Trace:" label.
var errorTraceRE = regexp.MustCompile(`Error Trace:\s+(\S+:\d+)`)

// errorMsgRE captures the inline message after a testify "Error:" label.
var errorMsgRE = regexp.MustCompile(`Error:\s+(.*)`)

// labeledLineRE detects the start of a new testify-style labeled section,
// used to stop collecting Error: continuation lines.
var labeledLineRE = regexp.MustCompile(`^\s*(Error Trace|Error|Test|Messages):\s`)

// extractErrorBlock walks failOutput looking for the last testify-style
// Error Trace and Error message. Returns the trace site (e.g.
// "foo_test.go:42") and the error message text including any indented
// continuation lines beneath the Error: label. Either may be empty if
// the test framework didn't emit testify-style output.
func extractErrorBlock(output []string) (errorMsg, traceSite string) {
	msgIdx := -1
	for i := len(output) - 1; i >= 0; i-- {
		if errorMsgRE.MatchString(output[i]) {
			msgIdx = i
			break
		}
	}
	if msgIdx >= 0 {
		if m := errorMsgRE.FindStringSubmatch(output[msgIdx]); len(m) >= 2 {
			errorMsg = strings.TrimSpace(m[1])
		}
		for j := msgIdx + 1; j < len(output); j++ {
			line := output[j]
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if labeledLineRE.MatchString(line) || strings.Contains(line, "--- FAIL") {
				break
			}
			if errorMsg == "" {
				errorMsg = trimmed
			} else {
				errorMsg += " " + trimmed
			}
			if len(errorMsg) > 300 {
				errorMsg = errorMsg[:300]
				break
			}
		}
	}

	for i := len(output) - 1; i >= 0; i-- {
		if m := errorTraceRE.FindStringSubmatch(output[i]); len(m) >= 2 {
			traceSite = m[1]
			break
		}
	}
	return errorMsg, traceSite
}

// fingerprintFromTestOutput picks an error fingerprint for a failed test.
// errorMsg (the testify Error: text, when present) takes precedence over
// snippet because it pinpoints the assertion that actually failed; this
// avoids attributing failures to incidental log noise. traceSite, if
// available, anchors the unknown-XXXX hash so the same assertion site
// groups together regardless of message wording.
func fingerprintFromTestOutput(errorMsg, snippet, traceSite string) string {
	if errorMsg != "" {
		for _, ep := range errorPatterns {
			if ep.regex.MatchString(errorMsg) {
				return ep.fingerprint
			}
		}
	}
	if snippet != "" {
		for _, ep := range errorPatterns {
			if ep.regex.MatchString(snippet) {
				return ep.fingerprint
			}
		}
	}
	if traceSite != "" {
		h := sha256.Sum256([]byte(traceSite))
		return fmt.Sprintf("unknown-%x", h[:4])
	}
	if errorMsg != "" {
		h := sha256.Sum256([]byte(errorMsg))
		return fmt.Sprintf("unknown-%x", h[:4])
	}
	for _, line := range strings.Split(snippet, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			h := sha256.Sum256([]byte(t))
			return fmt.Sprintf("unknown-%x", h[:4])
		}
	}
	return "unknown"
}

// enrichWithDockerLogs scans Docker log files in logDir and adds error
// fingerprints to failed test results.
func enrichWithDockerLogs(results []TestResult, logDir string) {
	if logDir == "" {
		return
	}

	logFiles := map[string]string{} // basename -> full path
	_ = filepath.WalkDir(logDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".log") {
			logFiles[filepath.Base(path)] = path
		}
		return nil
	})
	if len(logFiles) == 0 {
		return
	}

	logErrors := map[string]logError{}
	for basename, path := range logFiles {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if le, ok := parseDockerLogForError(f); ok {
			logErrors[basename] = le
		}
		f.Close()
	}

	applyDockerFingerprints(results, logFiles, logErrors)
}

func applyDockerFingerprints(results []TestResult, logFiles map[string]string, logErrors map[string]logError) {
	// Pre-compute fallback: most common fingerprint across all log files.
	var fallback logError
	if len(logErrors) > 0 {
		counts := map[string]int{}
		bestCount := 0
		for _, le := range logErrors {
			counts[le.fingerprint]++
			if counts[le.fingerprint] > bestCount {
				bestCount = counts[le.fingerprint]
				fallback = le
			}
		}
	}

	for i := range results {
		r := &results[i]
		if r.Outcome != "failed" && r.Outcome != "flaky-passed" {
			continue
		}

		// Try heuristic name matching first.
		matched := false
		for _, c := range generateLogCandidates(r.Test) {
			if _, ok := logFiles[c]; ok {
				if le, ok := logErrors[c]; ok {
					r.ErrorFingerprint = le.fingerprint
					if le.snippet != "" {
						r.ErrorSnippet = le.snippet
					}
					matched = true
					break
				}
			}
		}
		if matched {
			continue
		}

		// Fallback: most common fingerprint from all errored logs.
		// Only apply when the existing fingerprint is generic/unknown.
		if fallback.fingerprint != "" && isGenericFingerprint(r.ErrorFingerprint) {
			r.ErrorFingerprint = fallback.fingerprint
			if fallback.snippet != "" {
				r.ErrorSnippet = fallback.snippet
			}
		}
	}
}

// isGenericFingerprint returns true for fingerprints that should be
// overridden by a Docker log fallback (empty, unknown, exit-error).
func isGenericFingerprint(fp string) bool {
	return fp == "" || fp == "unknown" || fp == "exit-error" || strings.HasPrefix(fp, "unknown-")
}

func parseDockerLogForError(r io.Reader) (logError, bool) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Printf("warning: scanning Docker log: %v", err)
		return logError{}, false
	}

	start := len(lines) - 200
	if start < 0 {
		start = 0
	}
	for i := len(lines) - 1; i >= start; i-- {
		for _, ep := range errorPatterns {
			if ep.regex.MatchString(lines[i]) {
				snippet := strings.TrimSpace(lines[i])
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				return logError{fingerprint: ep.fingerprint, snippet: snippet}, true
			}
		}
	}
	return logError{}, false
}

var camelRE = regexp.MustCompile(`([a-z])([A-Z])`)

func generateLogCandidates(testName string) []string {
	name := strings.TrimPrefix(testName, "Test")
	name = camelRE.ReplaceAllString(name, "${1}-${2}")
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")

	candidates := []string{"test-suite-" + name + ".log"}
	if strings.HasPrefix(name, "suite-") {
		candidates = append(candidates, "test-suite-"+strings.TrimPrefix(name, "suite-")+".log")
	}
	return candidates
}
