// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

const (
	weaverContainer = "weaver"
	weaverAdminPort = 4320
	weaverTimeout   = 2 * time.Minute
)

// weaverIgnoredSignals lists signals whose violations are expected and should
// not cause the test to fail. target_info is a Prometheus/OpenMetrics convention
// (with Prometheus-style instance/job attributes) that is not part of the OTel
// semantic conventions registry.
// TODO: replace with custom override / filter once
// https://github.com/open-telemetry/weaver/pull/1256 is merged.
var weaverIgnoredSignals = map[string]struct{}{
	"metric:target_info": {},
}

func SemconvVersion() string {
	// semconv.SchemaURL is "https://opentelemetry.io/schemas/1.38.0"
	return semconv.SchemaURL[strings.LastIndex(semconv.SchemaURL, "/")+1:]
}

func weaverReportPath(t *testing.T) string {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "_")
	return path.Join(pathOutput, fmt.Sprintf("weaver-report-%s.json", name))
}

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

type weaverLiveCheckResult struct {
	AllAdvice []weaverAdvice `json:"all_advice"`
}

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

	ctx, cancel := context.WithTimeout(context.Background(), weaverTimeout)
	defer cancel()

	// Signal weaver to stop accepting data and produce its report.
	url := fmt.Sprintf("http://127.0.0.1:%d/stop", weaverAdminPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to stop weaver (is it running?): %v", err)
	}
	resp.Body.Close()
	require.Less(t, resp.StatusCode, 300, "weaver /stop returned HTTP %d", resp.StatusCode)

	// Wait for the weaver container to finish processing and exit.
	_, err = exec.CommandContext(ctx, "docker", "wait", weaverContainer).Output()
	if err != nil {
		t.Fatalf("failed to wait for weaver container: %v", err)
	}

	// Capture stdout (JSON report) and stderr (log lines) separately.
	// Weaver writes the JSON report to stdout and diagnostic messages to stderr.
	cmd := exec.CommandContext(ctx, "docker", "logs", weaverContainer)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to capture weaver logs: %v; stderr: %s", err, stderr.String())
	}

	// Save full output for later inspection.
	reportPath := weaverReportPath(t)
	require.NoError(t, os.WriteFile(reportPath, []byte(stdout.String()), 0o644),
		"failed to write weaver report to %s", reportPath)
	t.Logf("weaver report saved to %s", reportPath)
	if stderr.Len() > 0 {
		t.Logf("weaver diagnostics:\n%s", stderr.String())
	}

	// Parse the JSON report from stdout.
	jsonStr := strings.TrimSpace(stdout.String())
	if jsonStr == "" {
		t.Fatalf("weaver produced no JSON output on stdout")
	}

	var report weaverReport
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &report), "failed to parse weaver JSON report")

	validateWeaverReport(t, &report)
}

func validateWeaverReport(t *testing.T, report *weaverReport) {
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
	adviceByMsg := collectAdviceInfo(report.Samples)

	// Log all advisory messages grouped by level, and count actionable
	// violations (excluding signals listed in weaverIgnoredSignals).
	var actionableViolations int
	t.Logf("  advisory details:")
	for _, level := range []string{"violation", "improvement", "information"} {
		for msg, count := range stats.AdviceMessageCounts {
			info := adviceByMsg[msg]
			if info == nil {
				t.Logf("    [%s] [%dx] %s (signals: unknown)", level, count, msg)
				if level == "violation" {
					actionableViolations += count
				}
				continue
			}
			if info.Level != level {
				continue
			}
			signals := sortedSignals(info.Signals)
			ignored := allSignalsIgnored(info.Signals)
			suffix := ""
			if ignored {
				suffix = " [ignored]"
			}
			t.Logf("    [%s] [%dx] %s (signals: %s)%s", level, count, msg, strings.Join(signals, ", "), suffix)
			if level == "violation" && !ignored {
				actionableViolations += count
			}
		}
	}

	t.Logf("  violations: %d total, %d actionable (after ignoring %v)",
		violations, actionableViolations, sortedSignals(weaverIgnoredSignals))

	assert.Zero(t, actionableViolations,
		"weaver found %d actionable semantic convention violation(s)", actionableViolations)
}

// collectAdviceInfo scans all weaver samples to build a complete map from
// advisory message to its severity level and the set of signals that triggered it.
func collectAdviceInfo(samples []json.RawMessage) map[string]*adviceInfo {
	result := make(map[string]*adviceInfo)

	for _, raw := range samples {
		var generic map[string]json.RawMessage
		if json.Unmarshal(raw, &generic) != nil {
			continue
		}
		for _, v := range generic {
			extractAdviceInfo(v, result)
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

// allSignalsIgnored returns true if every signal in the set is in weaverIgnoredSignals.
func allSignalsIgnored(signals map[string]struct{}) bool {
	if len(signals) == 0 {
		return false
	}
	for sig := range signals {
		if _, ignored := weaverIgnoredSignals[sig]; !ignored {
			return false
		}
	}
	return true
}

func sortedSignals(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
