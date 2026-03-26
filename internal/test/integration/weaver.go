// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	weaverContainer  = "weaver"
	weaverAdminPort  = 4320
	weaverOutputFile = "weaver-report.json"
)

// weaverReport is the top-level JSON structure emitted by weaver with --format json.
type weaverReport struct {
	Samples    []json.RawMessage `json:"samples"`
	Statistics weaverStatistics  `json:"statistics"`
}

type weaverStatistics struct {
	TotalEntities       int            `json:"total_entities"`
	TotalEntitiesByType map[string]int `json:"total_entities_by_type"`
	TotalAdvisories     int            `json:"total_advisories"`
	AdviceLevelCounts   map[string]int `json:"advice_level_counts"`
	AdviceTypeCounts    map[string]int `json:"advice_type_counts"`
	AdviceMessageCounts map[string]int `json:"advice_message_counts"`
	RegistryCoverage    float64        `json:"registry_coverage"`
}

// weaverAdvice represents a single advisory finding from the weaver report.
type weaverAdvice struct {
	Message    string `json:"message"`
	Level      string `json:"level"`
	SignalType string `json:"signal_type"`
	SignalName string `json:"signal_name"`
}

// weaverLiveCheckResult is embedded in every entity that weaver evaluates.
type weaverLiveCheckResult struct {
	AllAdvice []weaverAdvice `json:"all_advice"`
}

// adviceInfo aggregates metadata about a unique advisory message.
type adviceInfo struct {
	Level   string
	Signals map[string]struct{} // set of "signal_type:signal_name"
}

// runWeaverValidation stops the weaver container (which runs as a service in
// the Docker Compose stack receiving OTLP from the collector) and validates
// that the emitted telemetry conforms to OpenTelemetry semantic conventions.
//
// This must be called while the Docker Compose stack is still running.
func runWeaverValidation(t *testing.T) {
	t.Helper()

	// Signal weaver to stop accepting data and produce its report.
	url := fmt.Sprintf("http://127.0.0.1:%d/stop", weaverAdminPort)
	resp, err := http.Post(url, "", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("failed to stop weaver (is it running?): %v", err)
	}
	resp.Body.Close()

	// Wait for the weaver container to finish processing and exit.
	exitCodeOutput, err := exec.Command("docker", "wait", weaverContainer).Output()
	if err != nil {
		t.Fatalf("failed to wait for weaver container: %v", err)
	}
	exitCode := strings.TrimSpace(string(exitCodeOutput))

	// Capture weaver's full output (report + diagnostics).
	output, _ := exec.Command("docker", "logs", weaverContainer).CombinedOutput()

	// Save raw output for later inspection.
	reportPath := path.Join(pathOutput, weaverOutputFile)
	_ = os.WriteFile(reportPath, output, 0o644)
	t.Logf("weaver report saved to %s", reportPath)

	// The output contains log lines before the JSON. Extract the JSON object.
	raw := string(output)
	jsonStart := strings.Index(raw, "\n{")
	if jsonStart == -1 {
		t.Logf("weaver output (no JSON found):\n%s", raw)
		t.Fatalf("could not find JSON report in weaver output")
	}
	jsonStr := raw[jsonStart:]
	// Trim any trailing non-JSON lines (e.g. "✔ Performed live check ...")
	if end := strings.LastIndex(jsonStr, "}"); end != -1 {
		jsonStr = jsonStr[:end+1]
	}

	var report weaverReport
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &report), "failed to parse weaver JSON report")

	validateWeaverReport(t, &report, exitCode)
}

// validateWeaverReport checks the parsed weaver report.
func validateWeaverReport(t *testing.T, report *weaverReport, exitCode string) {
	t.Helper()

	stats := &report.Statistics

	// Weaver must have received telemetry data.
	require.NotEmptyf(t, report.Samples,
		"weaver received no samples — OTLP data did not reach weaver")

	violations := stats.AdviceLevelCounts["violation"]

	t.Logf("weaver statistics:")
	t.Logf("  total entities:   %d", stats.TotalEntities)
	for typ, count := range stats.TotalEntitiesByType {
		t.Logf("    %-15s %d", typ, count)
	}
	t.Logf("  total advisories: %d", stats.TotalAdvisories)
	for level, count := range stats.AdviceLevelCounts {
		t.Logf("    %-15s %d", level, count)
	}
	t.Logf("  registry coverage: %.1f%%", stats.RegistryCoverage*100)

	// Build message → {level, signals} lookup from the sample data.
	adviceByMsg := collectAdviceInfo(report.Samples, stats.AdviceMessageCounts)

	// Log all advisory messages grouped by level.
	t.Logf("  advisory details:")
	for _, level := range []string{"violation", "improvement", "information"} {
		for msg, count := range stats.AdviceMessageCounts {
			info := adviceByMsg[msg]
			if info == nil || info.Level != level {
				continue
			}
			signals := sortedSignals(info.Signals)
			t.Logf("    [%s] [%dx] %s (signals: %s)", level, count, msg, strings.Join(signals, ", "))
		}
	}

	if exitCode != "0" {
		assert.Zero(t, violations,
			"weaver found %d semantic convention violation(s)", violations)
	}
}

// collectAdviceInfo scans the weaver samples to build a map from advisory
// message to its severity level and the set of signals that triggered it.
func collectAdviceInfo(samples []json.RawMessage, knownMessages map[string]int) map[string]*adviceInfo {
	result := make(map[string]*adviceInfo, len(knownMessages))

	for _, raw := range samples {
		var generic map[string]json.RawMessage
		if json.Unmarshal(raw, &generic) != nil {
			continue
		}
		for _, v := range generic {
			extractAdviceInfo(v, result)
		}
		// Stop early once we've resolved all known messages.
		if len(result) >= len(knownMessages) {
			break
		}
	}

	return result
}

// extractAdviceInfo recursively walks JSON looking for all_advice arrays
// and records message → {level, signals} mappings.
func extractAdviceInfo(data json.RawMessage, result map[string]*adviceInfo) {
	// Try as object with live_check_result or nested fields.
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) == nil {
		if lcr, ok := obj["live_check_result"]; ok {
			var checkResult weaverLiveCheckResult
			if json.Unmarshal(lcr, &checkResult) == nil {
				for i := range checkResult.AllAdvice {
					a := &checkResult.AllAdvice[i]
					info, exists := result[a.Message]
					if !exists {
						info = &adviceInfo{
							Level:   a.Level,
							Signals: make(map[string]struct{}),
						}
						result[a.Message] = info
					}
					if a.SignalName != "" {
						sig := a.SignalType + ":" + a.SignalName
						info.Signals[sig] = struct{}{}
					}
				}
			}
		}
		// Recurse into all values.
		for _, v := range obj {
			extractAdviceInfo(v, result)
		}
		return
	}

	// Try as array.
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) == nil {
		for _, item := range arr {
			extractAdviceInfo(item, result)
		}
	}
}

func sortedSignals(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
