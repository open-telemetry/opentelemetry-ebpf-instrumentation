// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

var spanSet = []request.Span{
	{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
}

var spanSetWithPaths = []request.Span{
	{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}, Path: "/something"},
	{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}, Path: "/v1/traces"},
	{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}, Path: "/v1/metrics"},
	{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
}

func TestFilter_SameNS(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := newPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	pf.AllowPID(123, 33, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(456, 33, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(789, 33, &svc.Attrs{}, PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))
}

func TestFilter_DifferentNS(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := newPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	pf.AllowPID(123, 22, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(456, 22, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(666, 22, &svc.Attrs{}, PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{}, resetTraceContext(pf.Filter(spanSet)))
}

func TestFilter_Block(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := newPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	pf.AllowPID(123, 33, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(456, 33, &svc.Attrs{}, PIDTypeGo)
	pf.BlockPID(123, 33)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []request.Span{
			{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		}, resetTraceContext(pf.Filter(spanSet)))
	}, 10*time.Second, 10*time.Millisecond, "still haven't seen pid 123 as blocked")
}

func TestFilter_NewNSLater(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := newPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	pf.AllowPID(123, 33, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(456, 33, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(789, 33, &svc.Attrs{}, PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))

	pf.AllowPID(1000, 44, &svc.Attrs{}, PIDTypeGo)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, resetTraceContext(pf.Filter(spanSet)))

	pf.BlockPID(456, 33)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, resetTraceContext(pf.Filter(spanSet)))

	pf.BlockPID(1000, 44)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))
}

func TestFilter_ExportsOTelDetection(t *testing.T) {
	const defaultOtlpPort = 4317
	pf := newPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	s := svc.Attrs{}
	span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/random/server/span", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTel(&s, &span, defaultOtlpPort)
	assert.False(t, s.ExportsOTelMetricsSpan())
	assert.False(t, s.ExportsOTelMetrics())
	assert.False(t, s.ExportsOTelTraces())

	s = svc.Attrs{}
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTel(&s, &span, defaultOtlpPort)
	assert.False(t, s.ExportsOTelMetricsSpan())
	assert.True(t, s.ExportsOTelMetrics())
	assert.False(t, s.ExportsOTelTraces())

	s = svc.Attrs{}
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTel(&s, &span, defaultOtlpPort)
	assert.False(t, s.ExportsOTelMetricsSpan())
	assert.False(t, s.ExportsOTelMetrics())
	assert.True(t, s.ExportsOTelTraces())
}

func TestFilter_ExportsOTelSpanDetection(t *testing.T) {
	const defaultOtlpPort = 4317
	pf := newPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	s := svc.Attrs{}
	span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/random/server/span", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTelSpanMetrics(&s, &span, defaultOtlpPort)
	assert.False(t, s.ExportsOTelMetricsSpan())
	assert.False(t, s.ExportsOTelMetrics())
	assert.False(t, s.ExportsOTelTraces())

	s = svc.Attrs{}
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTelSpanMetrics(&s, &span, defaultOtlpPort)
	assert.False(t, s.ExportsOTelMetricsSpan())
	assert.False(t, s.ExportsOTelMetrics())
	assert.False(t, s.ExportsOTelTraces())

	s = svc.Attrs{}
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTelSpanMetrics(&s, &span, defaultOtlpPort)
	assert.False(t, s.ExportsOTelMetrics())
	assert.True(t, s.ExportsOTelMetricsSpan())
	assert.False(t, s.ExportsOTelTraces())
	pf.checkIfExportsOTel(&s, &span, defaultOtlpPort)
	assert.True(t, s.ExportsOTelTraces())
}

func TestFilter_TriggersOTelFiltering(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := newPIDsFilter(&services.DiscoveryConfig{ExcludeOTelInstrumentedServices: true, ExcludeOTelInstrumentedServicesSpanMetrics: true}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	commonSvc := svc.Attrs{}
	pf.AllowPID(33, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(123, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(456, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(66, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(789, 33, &commonSvc, PIDTypeGo)

	testSpans := make([]request.Span, len(spanSetWithPaths))

	service := svc.Attrs{}

	for i := range spanSetWithPaths {
		testSpans[i] = spanSetWithPaths[i]
		testSpans[i].Service = service
		testSpans[i].Status = 200
		testSpans[i].Type = request.EventTypeHTTPClient
	}

	filtered := filterService(pf.Filter(testSpans))
	assert.Len(t, filtered, 5)

	// the first one didn't see any of the /v1/metrics, /v1/traces URLs in traffic
	assert.False(t, filtered[0].ExportsOTelMetrics())
	assert.False(t, filtered[0].ExportsOTelMetricsSpan())
	assert.False(t, filtered[0].ExportsOTelTraces())

	// second one saw /v1/traces so we marked both traces and span metrics as exported
	assert.False(t, filtered[1].ExportsOTelMetrics())
	assert.True(t, filtered[1].ExportsOTelMetricsSpan())
	assert.True(t, filtered[1].ExportsOTelTraces())

	// after the third, which has url /v1/metrics, we detected everything exported
	for i := 2; i < 5; i++ {
		assert.True(t, filtered[i].ExportsOTelMetrics())
		assert.True(t, filtered[i].ExportsOTelMetricsSpan())
		assert.True(t, filtered[i].ExportsOTelTraces())
	}
}

func TestFilter_TriggersOTelSpanFiltering(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := newPIDsFilter(&services.DiscoveryConfig{ExcludeOTelInstrumentedServices: true}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	commonSvc := svc.Attrs{}
	pf.AllowPID(33, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(123, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(456, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(66, 33, &commonSvc, PIDTypeGo)
	pf.AllowPID(789, 33, &commonSvc, PIDTypeGo)

	testSpans := make([]request.Span, len(spanSetWithPaths))

	service := svc.Attrs{}

	for i := range spanSetWithPaths {
		testSpans[i] = spanSetWithPaths[i]
		testSpans[i].Service = service
		testSpans[i].Status = 200
		testSpans[i].Type = request.EventTypeHTTPClient
	}

	filtered := filterService(pf.Filter(testSpans))
	assert.Len(t, filtered, 5)

	// the first one didn't see any of the /v1/metrics, /v1/traces URLs in traffic
	assert.False(t, filtered[0].ExportsOTelMetrics())
	assert.False(t, filtered[0].ExportsOTelMetricsSpan())
	assert.False(t, filtered[0].ExportsOTelTraces())

	// second one saw /v1/traces so we marked traces as exported, but not span metrics because the default config is false
	assert.False(t, filtered[1].ExportsOTelMetrics())
	assert.False(t, filtered[1].ExportsOTelMetricsSpan())
	assert.True(t, filtered[1].ExportsOTelTraces())

	// after the third, which has url /v1/metrics, we detected everything exported, but not span metrics
	for i := 2; i < 5; i++ {
		assert.True(t, filtered[i].ExportsOTelMetrics())
		assert.False(t, filtered[i].ExportsOTelMetricsSpan())
		assert.True(t, filtered[i].ExportsOTelTraces())
	}
}

func TestFilter_Cleanup(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		switch pid {
		case 123:
			return []uint32{uint32(pid), uint32(1)}, nil
		case 456:
			return []uint32{uint32(pid), uint32(2)}, nil
		case 789:
			return []uint32{uint32(pid), uint32(3)}, nil
		}
		assert.Fail(t, "fix your test, unknown pid")
		return nil, nil
	}
	pf := newPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	pf.AllowPID(123, 33, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(456, 33, &svc.Attrs{}, PIDTypeGo)
	pf.AllowPID(789, 33, &svc.Attrs{}, PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))

	// We should be able to filter on the other namespaced pids: 1, 2 and 3
	anotherSpanSet := []request.Span{
		{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 2, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 3, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 1, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 2, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 3, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(anotherSpanSet)))

	// We clean-up the first namespaced pids: 123, 456, 789. This should
	// also clean up: 1, 2, 3.
	pf.BlockPID(123, 33)
	pf.BlockPID(456, 33)
	pf.BlockPID(789, 33)

	assert.False(t, pf.ValidPID(1, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(2, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(3, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(333, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(666, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(234, 33, PIDTypeGo))
}

func resetTraceContext(spans []request.Span) []request.Span {
	for i := range spans {
		spans[i].TraceID = trace.TraceID{0}
		spans[i].SpanID = trace.SpanID{0}
		spans[i].TraceFlags = 0
	}

	return spans
}

func filterService(spans []request.Span) []svc.Attrs {
	result := []svc.Attrs{}
	for i := range spans {
		result = append(result, spans[i].Service)
	}

	return result
}
