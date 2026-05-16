// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	testPIDOTelService  uint32 = 33
	testPIDNonOTel      uint32 = 7
	testPIDFlagFlip     uint32 = 55
	testPIDDisabledGate uint32 = 42
	testPIDUntracked    uint32 = 99
)

func newTestTracer(t *testing.T, exclude bool) *Tracer {
	t.Helper()
	return &Tracer{
		log: slog.With("component", "logenricher-test"),
		cfg: &obi.Config{
			Discovery: services.DiscoveryConfig{
				ExcludeOTelInstrumentedServices: exclude,
			},
		},
		pids:        map[uint64][]uint64{},
		pidServices: map[uint32]*svc.Attrs{},
		pidsMU:      sync.Mutex{},
	}
}

func TestShouldOmitSpanID_FeatureDisabled(t *testing.T) {
	tr := newTestTracer(t, false)

	s := &svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}
	s.SetExportsOTelTraces()
	tr.pidServices[testPIDDisabledGate] = s

	assert.False(t, tr.shouldOmitSpanID(testPIDDisabledGate),
		"feature gate off: must not omit span_id even for OTel-exporting services")
}

func TestShouldOmitSpanID_UnknownPID(t *testing.T) {
	tr := newTestTracer(t, true)

	assert.False(t, tr.shouldOmitSpanID(testPIDUntracked),
		"unknown pid: fail-open, include span_id")
}

func TestShouldOmitSpanID_NonOTelService(t *testing.T) {
	tr := newTestTracer(t, true)

	tr.pidServices[testPIDNonOTel] = &svc.Attrs{UID: svc.UID{Name: "regular"}}

	assert.False(t, tr.shouldOmitSpanID(testPIDNonOTel),
		"non-OTel-exporting service: include span_id")
}

func TestShouldOmitSpanID_OTelService(t *testing.T) {
	tr := newTestTracer(t, true)

	s := &svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}
	s.SetExportsOTelTraces()
	tr.pidServices[testPIDOTelService] = s

	assert.True(t, tr.shouldOmitSpanID(testPIDOTelService),
		"OTel-exporting service with feature gate on: omit span_id")
}

func TestShouldOmitSpanID_ReflectsFlagFlip(t *testing.T) {
	tr := newTestTracer(t, true)

	s := &svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}
	tr.pidServices[testPIDFlagFlip] = s

	assert.False(t, tr.shouldOmitSpanID(testPIDFlagFlip),
		"before flag flip: include span_id")

	s.SetExportsOTelTraces()

	assert.True(t, tr.shouldOmitSpanID(testPIDFlagFlip),
		"after flag flip via shared pointer: omit span_id")
}

const (
	testTraceID = "00112233445566778899aabbccddeeff"
	testSpanID  = "0011223344556677"
	sdkTraceID  = "ffeeddccbbaa99887766554433221100"
	sdkSpanID   = "ffeeddccbbaa9988"
)

func TestApplyTraceContext_IncludeSpan(t *testing.T) {
	m := map[string]any{"message": "hello"}

	applyTraceContext(m, testTraceID, testSpanID, true)

	assert.Equal(t, testTraceID, m["trace_id"])
	assert.Equal(t, testSpanID, m["span_id"])
}

func TestApplyTraceContext_IncludeSpan_PreservesExisting(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID, "span_id": sdkSpanID}

	applyTraceContext(m, testTraceID, testSpanID, true)

	assert.Equal(t, sdkTraceID, m["trace_id"], "existing trace_id is preserved")
	assert.Equal(t, sdkSpanID, m["span_id"], "existing span_id is preserved")
}

func TestApplyTraceContext_IncludeSpan_FillsMissingSpanID(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID}

	applyTraceContext(m, testTraceID, testSpanID, true)

	assert.Equal(t, sdkTraceID, m["trace_id"], "existing trace_id is preserved")
	assert.Equal(t, testSpanID, m["span_id"], "missing span_id is filled")
}

func TestApplyTraceContext_OTelInstrumented_FillsMissingTraceID(t *testing.T) {
	m := map[string]any{"message": "hello"}

	applyTraceContext(m, testTraceID, testSpanID, false)

	assert.Equal(t, testTraceID, m["trace_id"])
	_, hasSpan := m["span_id"]
	assert.False(t, hasSpan, "OTel-instrumented: must not inject span_id")
}

func TestApplyTraceContext_OTelInstrumented_PreservesSDKTraceID(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID, "span_id": sdkSpanID}

	applyTraceContext(m, testTraceID, testSpanID, false)

	assert.Equal(t, sdkTraceID, m["trace_id"], "SDK's trace_id is preserved")
	assert.Equal(t, sdkSpanID, m["span_id"], "SDK's span_id is preserved")
}

func TestApplyTraceContext_OTelInstrumented_FillsTraceIDOnlyWhenSpanIDPresent(t *testing.T) {
	m := map[string]any{"span_id": sdkSpanID}

	applyTraceContext(m, testTraceID, testSpanID, false)

	assert.Equal(t, testTraceID, m["trace_id"], "OBI fills missing trace_id")
	assert.Equal(t, sdkSpanID, m["span_id"], "SDK's span_id stays untouched")
}
