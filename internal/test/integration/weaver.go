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

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

const (
	weaverContainer = "weaver"
	weaverAdminPort = 4320
	// weaverTimeout bounds the entire post-/stop sequence (HTTP /stop,
	// docker wait, docker cp of the report file, parse). The drain after
	// /stop scales with the unique signal count — heavy multi-language
	// suites need real headroom.
	weaverTimeout = 3 * time.Minute
)

// weaverIgnoredSignals is an escape hatch for advice we explicitly suppress
// without declaring the underlying signal in the OBI registry. Most non-semconv
// emissions (Prometheus `target_info`, OTel-contrib spanmetrics / service-graph
// shape, OBI-internal markers) are declared in `schemas/obi/` and validated
// against by weaver, so this map is intended to stay small. Add entries here
// only as a short-lived bridge while OBI catches up to a semconv contract.
var weaverIgnoredSignals = map[string]struct{}{
	// OBI emits `rpc.server.duration` and `rpc.client.duration` with
	// `unit: "s"`, but upstream semconv v1.38 (the version pinned in
	// `schemas/obi/manifest.yaml`) specifies `unit: "ms"` for these metrics.
	// Live-check resolves against the upstream definition and flags every
	// data point as a violation; declaring an override in our registry only
	// produces a duplicate-id warning at registry-check time without
	// changing live-check behavior. The unit reverts to `s` in semconv
	// v1.40.0, so these entries can drop once we bump the manifest's pinned
	// semconv version to >= 1.40.0.
	// TODO: remove once `schemas/obi/manifest.yaml` is bumped to semconv
	// >= 1.40.0 (which restores rpc duration to seconds).
	"metric:rpc.server.duration": {},
	"metric:rpc.client.duration": {},
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
	// OBI emits `iface` (interface name) alongside `iface.direction`, so
	// `iface` is both a leaf attribute *and* the namespace of another. The
	// emission contract is owned by netolly, mirrors the older
	// network-flow exporter convention, and is not negotiable for backward
	// compatibility — accept the structural warning.
	"Namespace 'iface' collides with existing attribute 'iface.direction'": {},
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

	priorFailure := t.Failed()
	if priorFailure {
		t.Logf("skipping weaver validation: prior test failure detected; " +
			"only stopping the weaver container so compose teardown is clean")
	}

	// weaver writes the report as root; delete via docker exec, not os.Remove.
	const hostReport = "/tmp/obi-weaver-out/live_check.json"
	const containerReport = "/tmp/weaver-out/live_check.json"
	rmCtx, rmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rmCancel()
	if _, err := docker.Exec(rmCtx, weaverContainer, "rm", "-f", containerReport); err != nil {
		t.Errorf("removing stale weaver report: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), weaverTimeout)
	defer cancel()

	// Signal weaver to stop accepting data and produce its report. If any
	// post-/stop step fails (timeout, container already killed, …) we record
	// the failure and force-remove the container so the surrounding
	// `compose.Close()` still runs and the next test invocation starts from
	// a clean slate.
	url := fmt.Sprintf("http://127.0.0.1:%d/stop", weaverAdminPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("failed to stop weaver (is it running?): %v", err)
		forceRemoveWeaverContainer(t)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Errorf("weaver /stop returned HTTP %d", resp.StatusCode)
		forceRemoveWeaverContainer(t)
		return
	}

	// Wait for the weaver container to finish processing and exit.
	if _, err = exec.CommandContext(ctx, "docker", "wait", weaverContainer).Output(); err != nil {
		t.Errorf("failed to wait for weaver container: %v", err)
		forceRemoveWeaverContainer(t)
		return
	}

	if priorFailure {
		return
	}

	reportPath := weaverReportPath(t)
	rawReport, err := os.ReadFile(hostReport)
	if err != nil {
		t.Errorf("failed to read weaver report at %s: %v", hostReport, err)
		return
	}
	if len(rawReport) == 0 {
		t.Errorf("weaver report file %s is empty", hostReport)
		return
	}
	if err := os.WriteFile(reportPath, rawReport, 0o644); err != nil {
		t.Logf("warn: failed to archive weaver report to %s: %v", reportPath, err)
	} else {
		t.Logf("weaver report saved to %s", reportPath)
	}
	var report weaverReport
	if err := json.Unmarshal(rawReport, &report); err != nil {
		t.Errorf("failed to parse weaver JSON report: %v", err)
		return
	}

	validateWeaverReport(t, &report)
}

// forceRemoveWeaverContainer is the best-effort cleanup we use when the normal
// /stop + docker-wait sequence couldn't finish. Without this, a stuck or
// killed weaver container survives the failed test invocation and the next
// run hits "container name already in use" (or, worse, a half-broken admin
// port that returns "connection reset by peer").
func forceRemoveWeaverContainer(t *testing.T) {
	t.Helper()
	rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(rmCtx, "docker", "rm", "-f", weaverContainer).CombinedOutput(); err != nil {
		t.Logf("failed to force-remove weaver container (already gone?): %v; output: %s", err, strings.TrimSpace(string(out)))
	}
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
