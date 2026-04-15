// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testMeta() RunMeta {
	return RunMeta{
		RunID:     "12345",
		SHA:       "abc",
		CreatedAt: "2026-01-01T00:00:00Z",
		Workflow:  "Pull request integration tests",
	}
}

func TestParseGotestsum(t *testing.T) {
	input := strings.Join([]string{
		// TestPassed
		`{"Time":"2026-01-01T00:00:00Z","Action":"run","Package":"pkg","Test":"TestPassed"}`,
		`{"Time":"2026-01-01T00:00:01Z","Action":"pass","Package":"pkg","Test":"TestPassed","Elapsed":1.0}`,
		// TestFailed
		`{"Time":"2026-01-01T00:00:00Z","Action":"run","Package":"pkg","Test":"TestFailed"}`,
		`{"Time":"2026-01-01T00:00:05Z","Action":"output","Package":"pkg","Test":"TestFailed","Output":"    Error: Received unexpected error:\n"}`,
		`{"Time":"2026-01-01T00:00:05Z","Action":"fail","Package":"pkg","Test":"TestFailed","Elapsed":5.0}`,
		// TestFlaky: fails then passes on rerun
		`{"Time":"2026-01-01T00:00:00Z","Action":"run","Package":"pkg","Test":"TestFlaky"}`,
		`{"Time":"2026-01-01T00:00:02Z","Action":"output","Package":"pkg","Test":"TestFlaky","Output":"    Error: connection refused\n"}`,
		`{"Time":"2026-01-01T00:00:02Z","Action":"fail","Package":"pkg","Test":"TestFlaky","Elapsed":2.0}`,
		`{"Time":"2026-01-01T00:00:10Z","Action":"run","Package":"pkg","Test":"TestFlaky"}`,
		`{"Time":"2026-01-01T00:00:12Z","Action":"pass","Package":"pkg","Test":"TestFlaky","Elapsed":2.0}`,
		// TestSkipped
		`{"Time":"2026-01-01T00:00:00Z","Action":"run","Package":"pkg","Test":"TestSkipped"}`,
		`{"Time":"2026-01-01T00:00:00Z","Action":"skip","Package":"pkg","Test":"TestSkipped","Elapsed":0.0}`,
	}, "\n")

	results, err := parseGotestsum(strings.NewReader(input), testMeta(), "shard-3")
	require.NoError(t, err)

	outcomes := map[string]string{}
	for _, r := range results {
		outcomes[r.Test] = r.Outcome
	}

	require.Equal(t, "passed", outcomes["TestPassed"])
	require.Equal(t, "failed", outcomes["TestFailed"])
	require.Equal(t, "flaky-passed", outcomes["TestFlaky"])
	require.Equal(t, "skipped", outcomes["TestSkipped"])
}

func TestParseGotestsum_Fingerprints(t *testing.T) {
	input := strings.Join([]string{
		`{"Time":"2026-01-01T00:00:00Z","Action":"run","Package":"pkg","Test":"TestTimeout"}`,
		`{"Time":"2026-01-01T00:00:30Z","Action":"output","Package":"pkg","Test":"TestTimeout","Output":"    Error: context deadline exceeded\n"}`,
		`{"Time":"2026-01-01T00:00:30Z","Action":"fail","Package":"pkg","Test":"TestTimeout","Elapsed":30.0}`,
		`{"Time":"2026-01-01T00:00:00Z","Action":"run","Package":"pkg","Test":"TestRace"}`,
		`{"Time":"2026-01-01T00:00:01Z","Action":"output","Package":"pkg","Test":"TestRace","Output":"WARNING: DATA RACE\n"}`,
		`{"Time":"2026-01-01T00:00:01Z","Action":"fail","Package":"pkg","Test":"TestRace","Elapsed":1.0}`,
	}, "\n")

	results, err := parseGotestsum(strings.NewReader(input), testMeta(), "shard-0")
	require.NoError(t, err)

	fps := map[string]string{}
	for _, r := range results {
		fps[r.Test] = r.ErrorFingerprint
	}

	require.Equal(t, "timeout", fps["TestTimeout"])
	require.Equal(t, "data-race", fps["TestRace"])
}

func TestParseDockerLogForError(t *testing.T) {
	log := "Container integration-testserver-1  Starting\n" +
		"Error response from daemon: Bind for 0.0.0.0:8381 failed: port is already allocated"

	le, ok := parseDockerLogForError(strings.NewReader(log))
	require.True(t, ok)
	require.Equal(t, "port-conflict", le.fingerprint)
	require.Contains(t, le.snippet, "port is already allocated")
}

func TestApplyDockerFingerprints(t *testing.T) {
	results := []TestResult{
		{Test: "TestFailed", Outcome: "failed", ErrorFingerprint: "exit-error"},
		{Test: "TestFlaky", Outcome: "flaky-passed", ErrorFingerprint: "connection-refused"},
		{Test: "TestUnknown", Outcome: "failed", ErrorFingerprint: "unknown"},
		{Test: "TestPassed", Outcome: "passed"},
	}

	logFiles := map[string]string{
		"test-suite-failed.log": "/logs/test-suite-failed.log",
	}
	logErrors := map[string]logError{
		"test-suite-failed.log": {fingerprint: "port-conflict", snippet: "port is already allocated"},
	}

	applyDockerFingerprints(results, logFiles, logErrors)

	// TestFailed matched heuristically via test-suite-failed.log
	require.Equal(t, "port-conflict", results[0].ErrorFingerprint)
	// TestFlaky: has specific fingerprint (connection-refused), fallback should NOT override
	require.Equal(t, "connection-refused", results[1].ErrorFingerprint)
	// TestUnknown: generic fingerprint, fallback SHOULD override
	require.Equal(t, "port-conflict", results[2].ErrorFingerprint)
	// TestPassed: not failed, untouched
	require.Empty(t, results[3].ErrorFingerprint)
}

func TestWriteReport(t *testing.T) {
	results := []TestResult{
		{RunID: "1", CreatedAt: "2026-01-01", Workflow: "Pull request integration tests", Test: "TestFailed", Outcome: "failed", ErrorFingerprint: "port-conflict"},
		{RunID: "1", CreatedAt: "2026-01-01", Workflow: "Pull request integration tests", Test: "TestFlaky", Outcome: "flaky-passed", ErrorFingerprint: "port-conflict"},
		{RunID: "1", CreatedAt: "2026-01-01", Workflow: "Pull request integration tests", Test: "TestPassed", Outcome: "passed"},
	}
	metaMap := map[string]RunMeta{
		"1": {RunID: "1", CreatedAt: "2026-01-01", Workflow: "Pull request integration tests", Conclusion: "failure"},
	}

	var buf bytes.Buffer
	err := writeReport(&buf, results, metaMap, "test/repo")
	require.NoError(t, err)

	report := buf.String()
	require.Contains(t, report, "# CI Test Analysis Report")
	require.Contains(t, report, "Pull request integration tests")
	require.Contains(t, report, "TestFailed")
	require.Contains(t, report, "TestFlaky")
	require.Contains(t, report, "port-conflict")
	require.Contains(t, report, "## Fingerprint Legend")

	// TestPassed should not appear as a flaky test row
	for _, line := range strings.Split(report, "\n") {
		if strings.Contains(line, "| `TestPassed`") {
			t.Errorf("TestPassed should not appear as a flaky test row")
		}
	}
}

func TestFingerprintUnknownHashing(t *testing.T) {
	// Two different unknown errors should get different fingerprints.
	fp1 := fingerprintFromTestOutput("some weird error A")
	fp2 := fingerprintFromTestOutput("some weird error B")
	require.Contains(t, fp1, "unknown-")
	require.Contains(t, fp2, "unknown-")
	require.NotEqual(t, fp1, fp2)

	// Same error should get the same fingerprint.
	require.Equal(t, fp1, fingerprintFromTestOutput("some weird error A"))

	// Empty snippet stays plain "unknown".
	require.Equal(t, "unknown", fingerprintFromTestOutput(""))
}

func TestClassifyOutcome(t *testing.T) {
	tests := []struct {
		name     string
		outcomes []string
		expected string
	}{
		{"pass only", []string{"pass"}, "passed"},
		{"fail only", []string{"fail"}, "failed"},
		{"fail then pass", []string{"fail", "pass"}, "flaky-passed"},
		{"skip only", []string{"skip"}, "skipped"},
		{"empty", nil, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, classifyOutcome(tt.outcomes))
		})
	}
}

func TestExtractErrorSnippet_Fallback(t *testing.T) {
	// No known error patterns — should fall back to last non-empty lines.
	output := []string{
		"=== RUN   TestWeird\n",
		"    some setup line\n",
		"    unexpected zorblax from server\n",
		"--- FAIL: TestWeird (1.00s)\n",
		"\n",
	}
	snippet := extractErrorSnippet(output)
	// "FAIL" matches a snippet pattern, so that line is captured.
	// But "unexpected zorblax" does not match any pattern — verify it
	// appears via the tail fallback if we strip the known-pattern lines.
	require.Contains(t, snippet, "FAIL")

	// Now test pure fallback: no patterns match at all.
	output = []string{
		"    some setup line\n",
		"    unexpected zorblax from server\n",
		"    another unknown line\n",
	}
	snippet = extractErrorSnippet(output)
	require.Contains(t, snippet, "unexpected zorblax from server")
	require.Contains(t, snippet, "another unknown line")
}

func TestGenerateLogCandidates(t *testing.T) {
	tests := []struct {
		testName string
		expected []string
	}{
		{"TestSuite_PythonTLS", []string{"test-suite-suite-python-tls.log", "test-suite-python-tls.log"}},
		{"TestMultiProcess", []string{"test-suite-multi-process.log"}},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			require.Equal(t, tt.expected, generateLogCandidates(tt.testName))
		})
	}
}
