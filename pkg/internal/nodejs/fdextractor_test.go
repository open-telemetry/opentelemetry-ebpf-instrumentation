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

// TestRuntimeMetricsFieldOrderMatchesEventStruct pins the order of the
// runtime-metrics fields the agent encodes to the wire order the BPF decoder
// assigns positionally (struct nodejs_eventloop_event in
// bpf/generictracer/types/nodejs.h, mirrored by nodejsEventLoopRawEvent in
// pkg/ebpf/common). The Go↔C layout is pinned by TestNodejsEventLoopRawABI;
// this closes the remaining JS↔C gap: reordering the array in fdextractor.js
// would silently swap metric values in production while every other test
// stays green.
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

// TestAgentCodeGatesRuntimeMetrics pins the injection-time substitution: the
// placeholder must exist exactly once in the script, stay false without the
// runtime-metrics feature, and flip to true with it. A drifted placeholder
// (e.g. reformatted by an editor) would silently leave runtime metrics off
// for every injection.
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
