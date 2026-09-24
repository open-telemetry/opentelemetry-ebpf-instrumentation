// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
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
	require.Equal(t, 1, strings.Count(_extractorCode, ctxHookEnabledPlaceholder),
		"CTX_HOOK_ENABLED placeholder missing or duplicated in fdextractor.js")

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
	require.Contains(t, tracesOnly.agentCode(), ctxHookEnabledPlaceholder,
		"tracing alone must not install the per-callback context hook")
}

// TestAgentCodeGatesCtxHook pins the before hook to the same predicate that
// drives the g_traces_ctx_v1_enabled BPF constant: it is installed only when
// something reads traces_ctx_v1.
func TestAgentCodeGatesCtxHook(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  obi.Config
	}{
		{
			name: "explicit opt-in",
			cfg: obi.Config{
				EBPF:         config.EBPFTracer{PopulateTraceContext: true},
				TracePrinter: "text",
			},
		},
		{
			name: "log enricher",
			cfg: obi.Config{
				EBPF: config.EBPFTracer{LogEnricher: config.LogEnricherConfig{
					Services: []config.LogEnricherServiceConfig{{}},
				}},
				TracePrinter: "text",
			},
		},
		{
			name: "manual spans",
			cfg: obi.Config{
				NodeJS:       obi.NodeJSConfig{Enabled: true, ManualSpans: true},
				TracePrinter: "text",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := (&NodeInjector{cfg: &tc.cfg}).agentCode()
			require.Equal(t, 1, strings.Count(code, ctxHookEnabledOn))
			require.Equal(t, 1, strings.Count(code, tracesEnabledOn),
				"the hook needs the propagation machinery it reads the fd from")
		})
	}

	// A metrics-only injection leaves the propagation machinery out, so the hook has
	// no ALS store to read the fd from even when the substitution enables it. The JS
	// keeps it inert by nesting it inside the TRACES_ENABLED block.
	metricsOnly := &NodeInjector{cfg: &obi.Config{
		EBPF:    config.EBPFTracer{PopulateTraceContext: true},
		Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
	}}
	code := metricsOnly.agentCode()
	require.Contains(t, code, tracesEnabledPlaceholder)

	tracesAt := strings.Index(code, "if (TRACES_ENABLED) {")
	require.NotEqual(t, -1, tracesAt, "traces block not found in fdextractor.js")
	hookAt := strings.Index(code, "if (CTX_HOOK_ENABLED) {")
	require.NotEqual(t, -1, hookAt, "ctx hook block not found in fdextractor.js")

	tracesEnd := matchingBrace(t, code, tracesAt+len("if (TRACES_ENABLED) "))
	require.True(t, tracesAt < hookAt && hookAt < tracesEnd,
		"the ctx hook must stay nested inside the traces gate")
}

// matchingBrace returns the index of the brace closing the one at open, skipping
// braces inside string literals and comments.
func matchingBrace(t *testing.T, src string, open int) int {
	t.Helper()
	require.Equal(t, byte('{'), src[open])

	depth := 0
	for i := open; i < len(src); i++ {
		switch c := src[i]; c {
		case '"', '\'', '`':
			for i++; i < len(src) && src[i] != c; i++ {
				if src[i] == '\\' {
					i++
				}
			}
		case '/':
			switch {
			case strings.HasPrefix(src[i:], "//"):
				i += strings.IndexByte(src[i:], '\n')
			case strings.HasPrefix(src[i:], "/*"):
				i += strings.Index(src[i:], "*/") + 1
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	require.Fail(t, "unbalanced braces in fdextractor.js")
	return -1
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

	// detail.kind exists since Node 16; the deprecated entry.kind accessor is
	// the only form on 14.10-15.x — dropping the fallback would silently kill
	// GC metrics on those runtimes
	require.Contains(t, src, "entry.detail ? entry.detail.kind : entry.kind",
		"gc kind must fall back to the pre-16 entry.kind accessor")
}

// TestV8ResourceEmissionFieldOrder pins the a-record wire layout: the
// fixed-width count first, the variable-length type name last (the path NUL
// terminates it), mirroring the h-record framing.
func TestV8ResourceEmissionFieldOrder(t *testing.T) {
	src := _extractorCode

	require.Equal(t, 1, strings.Count(src, "/dev/null/obi-v8/a"),
		"resource emission missing or duplicated in fdextractor.js")

	start := strings.Index(src, "/dev/null/obi-v8/a")
	end := strings.Index(src[start:], "`")
	require.NotEqual(t, -1, end, "resource template literal not terminated")
	block := src[start : start+end]

	countIdx := strings.Index(block, "rtHex(count)")
	typeIdx := strings.Index(block, "${type}")
	require.NotEqual(t, -1, countIdx, "count missing from the resource record")
	require.NotEqual(t, -1, typeIdx, "type name missing from the resource record")
	require.Greater(t, typeIdx, countIdx, "count must precede the type name on the wire")

	// an unguarded call would throw on pre-16.14 runtimes and terminate the app
	require.Contains(t, src, "typeof process.getActiveResourcesInfo === 'function'",
		"resource emission must be guarded for pre-16.14 runtimes")
}

// TestV8ResourceVanishedTypeZero pins the disappearing-type contract: a
// type absent from the current fold is emitted once with count 0, or the
// exporters would serve its stale last value until the staleness TTL.
func TestV8ResourceVanishedTypeZero(t *testing.T) {
	src := _extractorCode

	require.Contains(t, src, "orig.rtPrevResources || []",
		"the diff must iterate the previous tick's type set")
	require.Contains(t, src, "counts.set(type, 0)",
		"a vanished type must be emitted with an explicit zero count")
	require.Contains(t, src, "orig.rtPrevResources = present",
		"the previous-tick set must hold only the types actually present")

	// teardown must sit in the cleanup section before the RT gate
	gateStart := strings.Index(src, "if (RT_ENABLED &&")
	require.NotEqual(t, -1, gateStart, "RT gate not found in fdextractor.js")
	require.Contains(t, src[:gateStart], "orig.rtPrevResources = undefined",
		"rtPrevResources teardown must run outside the RT gate")
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
