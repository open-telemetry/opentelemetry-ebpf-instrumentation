// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/obi"
)

// TestRuntimeMetricsFieldOrderMatchesEventStruct pins the JS-side field order
// to the wire order the BPF decoder assigns positionally (struct
// nodejs_eventloop_event); the Go↔C layout is pinned by
// TestNodejsEventLoopRawABI. Reordering the array in fdextractor.js would
// silently swap metric values while every other test stays green.
func TestRuntimeMetricsFieldOrderMatchesEventStruct(t *testing.T) {
	src := _extractorCode

	start := strings.Index(src, "const fields = [")
	require.NotEqual(t, -1, start, "fields array not found in fdextractor.js")
	end := strings.Index(src[start:], "];")
	require.NotEqual(t, -1, end, "fields array not terminated in fdextractor.js")
	block := src[start : start+end]

	orderedFields := []string{
		"elu.idle",
		"elu.active",
		"h.min",
		"h.max",
		"h.mean",
		"h.stddev",
		"percentile(50)",
		"percentile(90)",
		"percentile(99)",
		"h.count",
	}
	pos := -1
	for _, field := range orderedFields {
		idx := strings.Index(block, field)
		require.NotEqual(t, -1, idx, "field %q missing from the fields array", field)
		require.Greater(t, idx, pos, "field %q out of order in the fields array", field)
		pos = idx
	}

	// one trailing comma per entry: catches added/removed fields, which
	// would shift every subsequent 16-hex-char slot on the wire
	require.Equal(t, len(orderedFields), strings.Count(block, ","),
		"unexpected number of entries in the fields array")
}

// TestAgentCodeGatesRuntimeMetrics pins the injection-time substitution: each
// placeholder must exist exactly once and flip only with its own config gate.
// A drifted placeholder would silently leave that machinery off for every
// injection.
func TestAgentCodeGatesRuntimeMetrics(t *testing.T) {
	require.Equal(t, 1, strings.Count(_extractorCode, rtEnabledPlaceholder),
		"RT_ENABLED placeholder missing or duplicated in fdextractor.js")
	require.Equal(t, 1, strings.Count(_extractorCode, tracesEnabledPlaceholder),
		"TRACES_ENABLED placeholder missing or duplicated in fdextractor.js")

	off := &NodeInjector{cfg: &obi.Config{}}
	require.Equal(t, _extractorCode, off.agentCode())

	metricsOnly := &NodeInjector{cfg: &obi.Config{
		Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
	}}
	require.Equal(t, 1, strings.Count(metricsOnly.agentCode(), rtEnabledOn))
	require.Contains(t, metricsOnly.agentCode(), tracesEnabledPlaceholder,
		"metrics-only injection must not enable trace propagation")

	tracesOnly := &NodeInjector{cfg: &obi.Config{TracePrinter: "text"}}
	require.Equal(t, 1, strings.Count(tracesOnly.agentCode(), tracesEnabledOn))
	require.Contains(t, tracesOnly.agentCode(), rtEnabledPlaceholder,
		"traces-only injection must not enable runtime sampling")
}

// TestV8HeapEmissionFieldOrder pins the h-record wire layout the BPF decoder
// assigns positionally: four fixed-width numbers in wire order, the
// variable-length space name LAST (the path NUL terminates it, so every
// number stays at a fixed offset).
func TestV8HeapEmissionFieldOrder(t *testing.T) {
	src := _extractorCode

	require.Equal(t, 1, strings.Count(src, "/dev/null/obi-v8/h"),
		"heap-space emission missing or duplicated in fdextractor.js")

	start := strings.Index(src, "/dev/null/obi-v8/h")
	end := strings.Index(src[start:], "`")
	require.NotEqual(t, -1, end, "heap-space template literal not terminated")
	block := src[start : start+end]

	orderedFields := []string{
		"space_size",
		"space_used_size",
		"space_available_size",
		"physical_space_size",
		"space_name",
	}
	pos := -1
	for _, field := range orderedFields {
		idx := strings.Index(block, field)
		require.NotEqual(t, -1, idx, "field %q missing from the heap-space record", field)
		require.Greater(t, idx, pos, "field %q out of order in the heap-space record", field)
		pos = idx
	}
}

// TestV8GCEmissionFieldOrder pins the g-record wire layout: one hex char with
// the Node GC-kind constant value, then the fixed-width duration. The
// PerformanceObserver reports durations in milliseconds; the record carries
// nanoseconds, so the conversion must sit inside the emission.
func TestV8GCEmissionFieldOrder(t *testing.T) {
	src := _extractorCode

	require.Equal(t, 1, strings.Count(src, "/dev/null/obi-v8/g"),
		"gc emission missing or duplicated in fdextractor.js")

	start := strings.Index(src, "/dev/null/obi-v8/g")
	end := strings.Index(src[start:], "`")
	require.NotEqual(t, -1, end, "gc template literal not terminated")
	block := src[start : start+end]

	kindIdx := strings.Index(block, "kind")
	durationIdx := strings.Index(block, "duration")
	require.NotEqual(t, -1, kindIdx, "gc kind missing from the gc record")
	require.NotEqual(t, -1, durationIdx, "gc duration missing from the gc record")
	require.Greater(t, durationIdx, kindIdx, "gc kind must precede the duration on the wire")

	require.Contains(t, block, "1e6",
		"gc duration must be converted from perf_hooks milliseconds to nanoseconds")
}

// TestV8MachineryFollowsRuntimeGate pins that the v8 collection lives and
// dies with the runtime-metrics gate: created once per injection, torn down
// on re-injection like the delay histogram, so a metrics-disabled
// re-injection leaves no observer running inside the application.
func TestV8MachineryFollowsRuntimeGate(t *testing.T) {
	src := _extractorCode

	require.Contains(t, src, "orig.gcObserver = ",
		"gc observer must be stored on the shared store for teardown")
	require.Contains(t, src, "orig.gcObserver.disconnect()",
		"re-injection must disconnect a previously installed gc observer")

	// the observer teardown must sit in the cleanup section that runs before
	// the RT gate, exactly like the rtHistogram teardown
	gateStart := strings.Index(src, "if (RT_ENABLED &&")
	require.NotEqual(t, -1, gateStart, "RT gate not found in fdextractor.js")
	require.Contains(t, src[:gateStart], "orig.gcObserver.disconnect()",
		"gc observer teardown must run outside the RT gate")
}
