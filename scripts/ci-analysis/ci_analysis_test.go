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
		CreatedAt: "2026-01-01T00:00:00Z",
		Workflow:  "Integration tests",
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

	results, err := parseGotestsum(strings.NewReader(input), testMeta())
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

	results, err := parseGotestsum(strings.NewReader(input), testMeta())
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
		{RunID: "1", Workflow: "Integration tests", Test: "TestFailed", Outcome: "failed", ErrorFingerprint: "port-conflict"},
		{RunID: "1", Workflow: "Integration tests", Test: "TestFlaky", Outcome: "flaky-passed", ErrorFingerprint: "port-conflict"},
		{RunID: "1", Workflow: "Integration tests", Test: "TestPassed", Outcome: "passed"},
	}
	metaMap := map[string]RunMeta{
		"1": {RunID: "1", Workflow: "Integration tests", Conclusion: "failure"},
	}

	var buf bytes.Buffer
	err := writeReport(&buf, "CI Test Analysis Report", results, metaMap, "test/repo")
	require.NoError(t, err)

	report := buf.String()
	require.Contains(t, report, "# CI Test Analysis Report")
	require.Contains(t, report, "Integration tests")
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
	fp1 := fingerprintFromTestOutput("", "some weird error A", "")
	fp2 := fingerprintFromTestOutput("", "some weird error B", "")
	require.Contains(t, fp1, "unknown-")
	require.Contains(t, fp2, "unknown-")
	require.NotEqual(t, fp1, fp2)

	// Same error should get the same fingerprint.
	require.Equal(t, fp1, fingerprintFromTestOutput("", "some weird error A", ""))

	// Empty inputs stay plain "unknown".
	require.Equal(t, "unknown", fingerprintFromTestOutput("", "", ""))
}

func TestFingerprintErrorMsgPriority(t *testing.T) {
	// Error message pattern wins over an incidental snippet pattern.
	// Here the snippet contains a panic from teardown but the actual
	// assertion was a connection-refused: connection-refused must win.
	snippet := "panic: goroutine teardown\n    Error: connection refused\n"
	fp := fingerprintFromTestOutput("connection refused", snippet, "")
	require.Equal(t, "connection-refused", fp)

	// When the error message has no recognized pattern, fall back to
	// the snippet scan.
	fp = fingerprintFromTestOutput("zorblax not converged", "WARNING: DATA RACE\n", "")
	require.Equal(t, "data-race", fp)
}

func TestFingerprintCauseConsequenceSplit(t *testing.T) {
	// testify explicitly reporting exit-status as the unexpected error:
	// the consequence pattern IS the cause here, keep the label.
	fp := fingerprintFromTestOutput(
		"Received unexpected error: exit status 1",
		"Error: Received unexpected error: exit status 1\n",
		"suites_test.go:337",
	)
	require.Equal(t, "exit-error", fp)

	// testify reports a generic assertion ("Condition never satisfied"),
	// while a teardown WARN line in the surrounding snippet contains
	// "exit status 1". The exit-error must NOT win — it's teardown noise
	// after the real assertion already failed. Expect trace-site hash.
	fp = fingerprintFromTestOutput(
		"Condition never satisfied",
		`WARN waiting for obi to stop. Will force remove error="exit status 1"`+"\n"+
			`Error: "3" is not less than or equal to "2"`+"\n"+
			"Error: Condition never satisfied\n",
		"red_test.go:424",
	)
	require.Contains(t, fp, "unknown-")
	require.NotEqual(t, "exit-error", fp)

	// Cause pattern in snippet still wins when errorMsg matches nothing —
	// a real panic must not be hidden behind a trace-site hash.
	fp = fingerprintFromTestOutput(
		"some unrelated assertion message",
		"panic: runtime error: nil pointer dereference\nError: some unrelated assertion message\n",
		"trace.go:1",
	)
	require.Equal(t, "panic", fp)

	// No testify Error: at all (non-framework failure). Consequence
	// patterns are the only signal — fall back to them.
	fp = fingerprintFromTestOutput("", "process exited with exit status 137\n", "")
	require.Equal(t, "exit-error", fp)

	// Two failures at the same outer wrapper but with different teardown
	// noise: must land in the same trace-site bucket.
	fpA := fingerprintFromTestOutput(
		"Condition never satisfied",
		`error="exit status 1"`+"\nError: Condition never satisfied\n",
		"red_test.go:424",
	)
	fpB := fingerprintFromTestOutput(
		"Condition never satisfied",
		"received signal: interrupt\nError: Condition never satisfied\n",
		"red_test.go:424",
	)
	require.Equal(t, fpA, fpB)
}

func TestFingerprintUnknownHashing_TraceSite(t *testing.T) {
	// Two failures at the same trace site should hash identically even
	// when the error wording differs slightly.
	fp1 := fingerprintFromTestOutput("expected 5 got 4", "", "foo_test.go:42")
	fp2 := fingerprintFromTestOutput("expected 7 got 3", "", "foo_test.go:42")
	require.Equal(t, fp1, fp2)
	require.Contains(t, fp1, "unknown-")

	// Different trace sites should hash differently.
	fp3 := fingerprintFromTestOutput("expected 5 got 4", "", "bar_test.go:99")
	require.NotEqual(t, fp1, fp3)
}

func TestExtractErrorBlock_IgnoresUnanchoredErrorLines(t *testing.T) {
	// Application log lines that contain "Error:" or "Error Trace:" must
	// not be picked up as the testify framework error. Only indented
	// labeled lines (testify's emission style) should match.
	output := []string{
		"Error: app log before testify\n",
		"2026/04/29 13:48:19 ERROR Error Trace: spurious.go:1\n",
		"        \tError Trace:\tfoo_test.go:42\n",
		"        \tError:      \tReal testify failure\n",
		"--- FAIL: TestX (0.50s)\n",
		"Error: app log after the FAIL marker\n",
	}
	msg, trace := extractErrorBlock(output)
	require.Equal(t, "foo_test.go:42", trace)
	require.Equal(t, "Real testify failure", msg)
}

func TestExtractErrorBlock(t *testing.T) {
	// testify-style output with Error Trace, Error: with a continuation
	// line, then Test: label and FAIL marker.
	output := []string{
		"=== RUN   TestX\n",
		"    file_test.go:25: \n",
		"        \tError Trace:\tfoo_test.go:42\n",
		"        \tError:      \tReceived unexpected error:\n",
		"        \t            \tconnection refused\n",
		"        \tTest:       \tTestX\n",
		"--- FAIL: TestX (0.50s)\n",
	}
	msg, trace := extractErrorBlock(output)
	require.Equal(t, "foo_test.go:42", trace)
	require.Contains(t, msg, "Received unexpected error:")
	require.Contains(t, msg, "connection refused")
	// Continuation collection must stop at the Test: label.
	require.NotContains(t, msg, "TestX")

	// Output with no testify labels returns empty values.
	msg, trace = extractErrorBlock([]string{"=== RUN   TestY\n", "panic: nope\n"})
	require.Empty(t, msg)
	require.Empty(t, trace)

	// When multiple Error: blocks are present, the last one wins.
	output = []string{
		"        \tError Trace:\tfirst.go:10\n",
		"        \tError:      \tearly failure\n",
		"        \tError Trace:\tsecond.go:20\n",
		"        \tError:      \tlate failure\n",
	}
	msg, trace = extractErrorBlock(output)
	require.Equal(t, "second.go:20", trace)
	require.Contains(t, msg, "late failure")
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

func TestComputeTestStats_ScopedPerWorkflow(t *testing.T) {
	// Same test name running in two workflows must be tracked separately so
	// the flaky-table Workflow/Runs columns stay consistent.
	results := []TestResult{
		{RunID: "1", Workflow: "WfA", Test: "TestX", Outcome: "passed"},
		{RunID: "1", Workflow: "WfB", Test: "TestX", Outcome: "failed", ErrorFingerprint: "timeout"},
		{RunID: "2", Workflow: "WfA", Test: "TestX", Outcome: "flaky-passed", ErrorFingerprint: "port-conflict"},
		{RunID: "2", Workflow: "WfB", Test: "TestX", Outcome: "passed"},
	}
	tests := computeTestStats(results)
	require.Len(t, tests, 2)

	var wfA, wfB *testStats
	for _, ts := range tests {
		switch ts.workflow {
		case "WfA":
			wfA = ts
		case "WfB":
			wfB = ts
		}
	}
	require.NotNil(t, wfA)
	require.NotNil(t, wfB)

	require.Equal(t, 2, wfA.totalRuns)
	require.Equal(t, 1, wfA.passed)
	require.Equal(t, 1, wfA.flakyPassed)
	require.Equal(t, 0, wfA.failed)

	require.Equal(t, 2, wfB.totalRuns)
	require.Equal(t, 1, wfB.passed)
	require.Equal(t, 1, wfB.failed)
	require.Equal(t, 0, wfB.flakyPassed)

	// Tests-tracked count must collapse the same name across workflows.
	require.Equal(t, 1, countUniqueTests(tests))
}

func TestComputeTestStats_SameNameDifferentPackages(t *testing.T) {
	// Unit-test shards run multiple Go packages in one gotestsum file. Two
	// tests sharing a name across packages must stay distinct in the
	// aggregation, otherwise their results get silently merged.
	results := []TestResult{
		{RunID: "1", Workflow: "Wf", Package: "pkg/a", Test: "TestNew", Outcome: "passed"},
		{RunID: "1", Workflow: "Wf", Package: "pkg/b", Test: "TestNew", Outcome: "failed", ErrorFingerprint: "timeout"},
	}
	tests := computeTestStats(results)
	require.Len(t, tests, 2, "same name in two packages must produce two stats entries")

	byPkg := map[string]*testStats{}
	for _, ts := range tests {
		byPkg[ts.pkg] = ts
	}
	require.Equal(t, 1, byPkg["pkg/a"].passed)
	require.Equal(t, 0, byPkg["pkg/a"].failed)
	require.Equal(t, 0, byPkg["pkg/b"].passed)
	require.Equal(t, 1, byPkg["pkg/b"].failed)
}

func TestParseGotestsum_SameNameDifferentPackages(t *testing.T) {
	// parseGotestsum's internal state map must key by (package, test) — a
	// single gotestsum file from a unit-test shard can contain events for
	// multiple packages with overlapping test names.
	input := strings.Join([]string{
		`{"Action":"run","Package":"pkg/a","Test":"TestNew"}`,
		`{"Action":"pass","Package":"pkg/a","Test":"TestNew"}`,
		`{"Action":"run","Package":"pkg/b","Test":"TestNew"}`,
		`{"Action":"output","Package":"pkg/b","Test":"TestNew","Output":"    Error: connection refused\n"}`,
		`{"Action":"fail","Package":"pkg/b","Test":"TestNew"}`,
	}, "\n")
	results, err := parseGotestsum(strings.NewReader(input), testMeta())
	require.NoError(t, err)
	require.Len(t, results, 2)

	byPkg := map[string]TestResult{}
	for _, r := range results {
		byPkg[r.Package] = r
	}
	require.Equal(t, "passed", byPkg["pkg/a"].Outcome)
	require.Equal(t, "failed", byPkg["pkg/b"].Outcome)
}

func TestDisplayTestName(t *testing.T) {
	// Package leaf prefixes the test name; empty package falls back to bare.
	require.Equal(t, "ebpf.TestNew", displayTestName("go.opentelemetry.io/obi/pkg/components/ebpf", "TestNew"))
	require.Equal(t, "pkg.TestNew", displayTestName("pkg", "TestNew"))
	require.Equal(t, "TestNoPkg", displayTestName("", "TestNoPkg"))
}

func TestComputeFingerprintStats_AffectedTestsCountsByPackage(t *testing.T) {
	// Two distinct tests sharing a name in different packages must count as
	// two affected tests, not one.
	results := []TestResult{
		{RunID: "1", Workflow: "Wf", Package: "pkg/a", Test: "TestNew", Outcome: "failed", ErrorFingerprint: "timeout"},
		{RunID: "1", Workflow: "Wf", Package: "pkg/b", Test: "TestNew", Outcome: "failed", ErrorFingerprint: "timeout"},
	}
	stats := computeFingerprintStats(results)
	require.Len(t, stats, 1)
	require.Len(t, stats[0].affectedTests, 2, "affectedTests must distinguish packages")
}

func TestWriteReport_RendersPackageQualifiedNames(t *testing.T) {
	// Every test row should display "pkg-leaf.TestName" so identities are
	// stable and same-named tests in different packages are distinguishable.
	results := []TestResult{
		{RunID: "1", Workflow: "Wf", Package: "go.test/pkg/a", Test: "TestNew", Outcome: "failed", ErrorFingerprint: "timeout"},
		{RunID: "1", Workflow: "Wf", Package: "go.test/pkg/b", Test: "TestNew", Outcome: "failed", ErrorFingerprint: "timeout"},
	}
	metaMap := map[string]RunMeta{
		"1": {RunID: "1", Workflow: "Wf", Conclusion: "failure"},
	}
	var buf bytes.Buffer
	require.NoError(t, writeReport(&buf, "CI Test Analysis Report", results, metaMap, "test/repo"))

	out := buf.String()
	require.Contains(t, out, "`a.TestNew`", "rows should include the package leaf; got:\n%s", out)
	require.Contains(t, out, "`b.TestNew`")
	require.NotContains(t, out, "| `TestNew` |", "bare test name should not appear when a package is set")
}

func TestComputeTestStats_DedupShardsPerRun(t *testing.T) {
	// A test that appears in multiple shards within the same run counts as
	// one run; the worst outcome wins.
	results := []TestResult{
		{RunID: "1", Workflow: "Wf", Test: "TestX", Outcome: "passed"},
		{RunID: "1", Workflow: "Wf", Test: "TestX", Outcome: "failed", ErrorFingerprint: "timeout"},
		{RunID: "2", Workflow: "Wf", Test: "TestX", Outcome: "passed"},
	}
	tests := computeTestStats(results)
	require.Len(t, tests, 1)
	for _, ts := range tests {
		require.Equal(t, 2, ts.totalRuns, "two CI runs, even though run 1 had two shards")
		require.Equal(t, 1, ts.failed, "run 1 collapses to failed because failed > passed")
		require.Equal(t, 1, ts.passed)
	}
}

func TestComputeTestStats_SkippedExcludedFromTotal(t *testing.T) {
	// Skipped runs must not pad the denominator of the failure rate.
	results := []TestResult{
		{RunID: "1", Workflow: "Wf", Test: "TestX", Outcome: "skipped"},
		{RunID: "2", Workflow: "Wf", Test: "TestX", Outcome: "skipped"},
		{RunID: "3", Workflow: "Wf", Test: "TestX", Outcome: "failed", ErrorFingerprint: "timeout"},
	}
	tests := computeTestStats(results)
	require.Len(t, tests, 1)
	for _, ts := range tests {
		require.Equal(t, 1, ts.totalRuns, "only the attempted run counts toward Runs")
		require.Equal(t, 1, ts.failed)
		require.Equal(t, 2, ts.skipped)
	}
}

func TestWriteReport_PassRateMatchesConclusion(t *testing.T) {
	// A workflow whose runs all eventually succeeded (with flaky retries)
	// should show 100% pass rate, not 0% — that matches GitHub's run
	// conclusion, which is what users see in the Actions tab.
	results := []TestResult{
		{RunID: "1", Workflow: "Wf", Test: "TestX", Outcome: "flaky-passed", ErrorFingerprint: "timeout"},
		{RunID: "2", Workflow: "Wf", Test: "TestX", Outcome: "passed"},
	}
	metaMap := map[string]RunMeta{
		"1": {RunID: "1", Workflow: "Wf", Conclusion: "success"},
		"2": {RunID: "2", Workflow: "Wf", Conclusion: "success"},
	}
	var buf bytes.Buffer
	require.NoError(t, writeReport(&buf, "CI Test Analysis Report", results, metaMap, "test/repo"))

	report := buf.String()
	// Workflow row format: | Wf | 2 | 1 | 1 | 0 | 100% |
	require.Contains(t, report, "| Wf | 2 | 1 | 1 | 0 | 100% |",
		"flaky-passed runs should not lower the pass rate; report was:\n%s", report)
}

func TestWriteReport_HardFailLowersPassRate(t *testing.T) {
	results := []TestResult{
		{RunID: "1", Workflow: "Wf", Test: "TestX", Outcome: "failed", ErrorFingerprint: "timeout"},
		{RunID: "2", Workflow: "Wf", Test: "TestX", Outcome: "passed"},
	}
	metaMap := map[string]RunMeta{
		"1": {RunID: "1", Workflow: "Wf", Conclusion: "failure"},
		"2": {RunID: "2", Workflow: "Wf", Conclusion: "success"},
	}
	var buf bytes.Buffer
	require.NoError(t, writeReport(&buf, "CI Test Analysis Report", results, metaMap, "test/repo"))

	require.Contains(t, buf.String(), "| Wf | 2 | 1 | 0 | 1 | 50% |")
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
