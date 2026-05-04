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

// weaverIgnoredSignals is an escape hatch for advice we explicitly suppress
// without declaring the underlying signal in the OBI registry. Most non-semconv
// emissions (Prometheus `target_info`, OTel-contrib spanmetrics / service-graph
// shape, OBI-internal markers) are declared in `schemas/obi/` and validated
// against by weaver, so this map is intended to stay small. Add entries here
// only as a short-lived bridge while OBI catches up to a semconv contract.
var weaverIgnoredSignals = map[string]struct{}{
	// OBI emits `rpc.server.duration` with `unit: "s"`, but upstream semconv
	// v1.38 (the version pinned in `schemas/obi/manifest.yaml`) specifies
	// `unit: "ms"` for this metric. Live-check resolves against the upstream
	// definition and flags every data point as a violation; declaring an
	// override in our registry only produces a duplicate-id warning at
	// registry-check time without changing live-check behaviour. The unit
	// reverts to `s` in semconv v1.40.0, so this entry can drop once we bump
	// the manifest's pinned semconv version to >= 1.40.0.
	// TODO: remove once `schemas/obi/manifest.yaml` is bumped to semconv
	// >= 1.40.0 (which restores `rpc.server.duration` to seconds).
	"metric:rpc.server.duration": {},
}

// weaverIgnoredAdviceMessages suppresses specific advice messages that match
// known structural tensions weaver reports against the registry as a whole
// rather than against any one signal. Today this only covers the `server` /
// `client` namespace collision: the OTel collector-contrib `servicegraphconnector`
// emits bare `server` / `client` labels (matched in `service_graph.yaml`), but
// upstream semconv reserves `server.*` / `client.*` as namespace prefixes
// (`server.address`, `server.port`, …). Weaver's lint flags the registry-level
// collision on every signal that touches an upstream `server.*` / `client.*`
// attribute, even ones that don't use the bare label. The contract OBI emits
// is fixed by the connector convention; the ignore documents the tension.
var weaverIgnoredAdviceMessages = map[string]struct{}{
	"Namespace 'server' collides with existing attribute 'server.address'": {},
	"Namespace 'server' collides with existing attribute 'server.port'":    {},
	"Namespace 'client' collides with existing attribute 'client.address'": {},
	"Namespace 'client' collides with existing attribute 'client.port'":    {},
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
//
// If the parent test has already failed (e.g. a sub-test exposed an OBI bug
// or the test environment couldn't produce telemetry), validation is skipped
// to avoid burying the real failure under cascading "weaver received no
// samples" noise. We still POST /stop and `docker wait` so the weaver
// container exits cleanly for `compose.Close()`.
func runWeaverValidation(t *testing.T) {
	t.Helper()

	priorFailure := t.Failed()
	if priorFailure {
		t.Logf("skipping weaver validation: prior test failure detected; " +
			"only stopping the weaver container so compose teardown is clean")
	}

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

	// If a prior sub-test already failed, the weaver report would either be
	// empty (no telemetry produced) or only reflect a partial run. Either
	// way it's not the real signal — skip parsing & assertions so the
	// upstream failure stays the headline.
	if priorFailure {
		return
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

	// Parse the JSON report from stdout. Weaver may emit diagnostic JSON
	// records (for example duplicate-id warnings on registry resolution)
	// alongside the report; the live-check report itself is the value with
	// `samples` and `statistics` fields. Iterate top-level JSON objects and
	// pick the one that matches the report shape.
	jsonStr := strings.TrimSpace(stdout.String())
	if jsonStr == "" {
		t.Fatalf("weaver produced no JSON output on stdout")
	}
	report, err := decodeWeaverReport(jsonStr)
	require.NoError(t, err, "failed to parse weaver JSON report")

	validateWeaverReport(t, report)
}

// decodeWeaverReport scans `s` for top-level JSON objects and returns the
// first one that matches the live-check report shape (non-nil `Statistics`
// or non-empty `Samples`). Other top-level JSON values (e.g. diagnostic
// records) are skipped.
func decodeWeaverReport(s string) (*weaverReport, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	var lastErr error
	var lastReport *weaverReport
	for dec.More() {
		var probe weaverReport
		if err := dec.Decode(&probe); err != nil {
			lastErr = err
			break
		}
		// Heuristic: a live-check report has non-zero statistics or at least
		// one sample. Anything else (diagnostics, error envelopes) wouldn't
		// populate these.
		if probe.Statistics.TotalEntities > 0 || probe.Statistics.TotalAdvisories > 0 || len(probe.Samples) > 0 {
			r := probe
			return &r, nil
		}
		r := probe
		lastReport = &r
	}
	if lastReport != nil {
		return lastReport, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no weaver report found in %d bytes of output", len(s))
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
			_, msgIgnored := weaverIgnoredAdviceMessages[msg]
			info := adviceByMsg[msg]
			if info == nil {
				if level != "violation" {
					continue
				}

				suffix := ""
				if msgIgnored {
					suffix = " [ignored]"
				}
				t.Logf("    [%s] [%dx] %s (signals: unknown)%s", level, count, msg, suffix)
				if !msgIgnored {
					actionableViolations += count
				}
				continue
			}
			if info.Level != level {
				continue
			}
			signals := sortedSignals(info.Signals)
			ignored := msgIgnored || allSignalsIgnored(info.Signals)
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
