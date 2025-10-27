// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/transform"
	"go.opentelemetry.io/obi/test/collector"
)

const testTimeout = 5 * time.Second

func gctx(groups attributes.AttrGroups, mcfg *otelcfg.MetricsConfig) *global.ContextInfo {
	return &global.ContextInfo{
		Metrics:               imetrics.NoopReporter{},
		MetricAttributeGroups: groups,
		K8sInformer:           kube.NewMetadataProvider(kube.MetadataConfig{Enable: kubeflags.EnabledFalse}, imetrics.NoopReporter{}),
		HostID:                "host-id",
		OTELMetricsExporter:   &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	}
}

var allMetrics = attributes.Selection{
	"*": attributes.InclusionLists{Include: []string{"*"}},
}

func allMetricsBut(patterns ...string) attributes.Selection {
	return attributes.Selection{
		attributes.HTTPServerDuration.Section: attributes.InclusionLists{
			Include: []string{"*"},
			Exclude: patterns,
		},
	}
}

func TestBasicPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	cfg := otelcfg.MetricsConfig{
		Features:        []string{otelcfg.FeatureApplication},
		MetricsEndpoint: tc.ServerEndpoint, Interval: 10 * time.Millisecond,
		ReportersCacheLen: 16,
		TTL:               5 * time.Minute,
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
	}
	gb := newGraphBuilder(&obi.Config{
		NameResolver: obi.DefaultConfig.NameResolver,
		Metrics:      cfg,
		Attributes:   obi.Attributes{Select: allMetrics, InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"}},
	}, gctx(0, &cfg), tracesInput, processEvents)

	// Override eBPF tracer to send some fake data
	tracesInput.Send(newRequest("foo-svc", "/foo/bar", 404))
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	start := time.Now()
	var event collector.MetricRecord
	for {
		event = testutil.ReadChannel(t, tc.Records(), testTimeout)
		assert.NotEmpty(t, event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
		delete(event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
		assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
		delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
		if event.Name == "http.server.request.duration" {
			break
		}
		t.Logf("skipping event %s", event.Name)
		if time.Since(start) > testTimeout {
			t.Fatalf("timeout waiting for request.duration event")
		}
	}

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.request.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(attr.HTTPRequestMethod):      "GET",
			string(attr.HTTPResponseStatusCode): "404",
			string(attr.HTTPUrlPath):            "/foo/bar",
			string(attr.ClientAddr):             "1.1.1.1",
			string(semconv.ServiceNameKey):      "foo-svc",
			string(semconv.ServiceNamespaceKey): "ns",
			string(attr.ServerPort):             "8080",
			string(attr.ServerAddr):             event.Attributes["server.address"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "foo-svc",
			string(semconv.ServiceNamespaceKey):     "ns",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
		},
		Type:     pmetric.MetricTypeHistogram,
		FloatVal: 2 / float64(time.Second),
		Count:    1,
	}, event)

	cancel()
	require.NoError(t, <-done)
}

func TestTracerPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	gCtx := gctx(0, nil)
	gCtx.ExtraResourceAttributes = []attribute.KeyValue{attribute.String("overridden", "attr")}

	gb := newGraphBuilder(&obi.Config{
		Traces: otelcfg.TracesConfig{
			BatchTimeout:      10 * time.Millisecond,
			MaxQueueSize:      10,
			TracesEndpoint:    tc.ServerEndpoint,
			ReportersCacheLen: 16,
			Instrumentations:  []string{instrumentations.InstrumentationALL},
		},
		Attributes: obi.Attributes{InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"}},
	}, gCtx, tracesInput, processEvents)

	// Override eBPF tracer to send some fake data
	tracesInput.Send(newRequest("bar-svc", "/foo/bar", 404))

	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchInnerTraceEvent(t, "in queue", event)
	event = testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchInnerTraceEvent(t, "processing", event)
	event = testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchTraceEvent(t, "GET", event)

	cancel()
	require.NoError(t, <-done)
}

func TestMergedMetricsTracePipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	mCfg := otelcfg.MetricsConfig{
		Features:        []string{otelcfg.FeatureApplication},
		MetricsEndpoint: tc.ServerEndpoint, Interval: 10 * time.Millisecond,
		ReportersCacheLen: 16,
		TTL:               5 * time.Minute,
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
	}
	tCfg := otelcfg.TracesConfig{
		BatchTimeout:      10 * time.Millisecond,
		MaxQueueSize:      10,
		TracesEndpoint:    tc.ServerEndpoint,
		ReportersCacheLen: 16,
		Instrumentations:  []string{instrumentations.InstrumentationALL},
	}

	gb := newGraphBuilder(&obi.Config{
		Metrics: mCfg,
		Traces:  tCfg,
		Attributes: obi.Attributes{
			Select:                         allMetrics,
			InstanceID:                     config.InstanceIDConfig{OverrideHostname: "the-host"},
			MetricSpanNameAggregationLimit: 10,
		},
	}, gctx(0, &mCfg), tracesInput, processEvents)

	tracesInput.Send(newRequest("bar-svc", "/foo/bar", 404))

	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)
	done := pipe.Start(ctx)

	// Test that traces flow through the pipeline to the end
	event := testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	assert.Equal(t, "in queue", event.Name)
	event = testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	assert.Equal(t, "processing", event.Name)
	event = testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	assert.Equal(t, "GET", event.Name)

	// Test that metrics flow through the pipeline to the end

	cancel()
	require.NoError(t, testutil.ReadChannel(t, done, testTimeout))
}

func TestTracerPipelineBadTimestamps(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	gb := newGraphBuilder(&obi.Config{
		Traces: otelcfg.TracesConfig{
			BatchTimeout:      10 * time.Millisecond,
			TracesEndpoint:    tc.ServerEndpoint,
			ReportersCacheLen: 16,
			Instrumentations:  []string{instrumentations.InstrumentationALL},
		},
	}, gctx(0, nil), tracesInput, processEvents)
	// Override eBPF tracer to send some fake data
	tracesInput.Send(newRequestWithTiming("svc1", request.EventTypeHTTP, "GET", "/attach", 200, 60000, 59999, 70000))
	// closing prematurely the input node would finish the whole graph processing
	// and OTEL exporters could be closed, so we wait.
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchNestedEvent(t, "GET", "GET", "/attach", "200", ptrace.SpanKindServer, event)

	cancel()
	require.NoError(t, <-done)
}

func TestRouteConsolidation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))

	cfg := otelcfg.MetricsConfig{
		SDKLogLevel:     "debug",
		Features:        []string{otelcfg.FeatureApplication},
		MetricsEndpoint: tc.ServerEndpoint, Interval: 10 * time.Millisecond,
		ReportersCacheLen: 16,
		TTL:               5 * time.Minute,
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
	}
	gb := newGraphBuilder(&obi.Config{
		Metrics:    cfg,
		Routes:     &transform.RoutesConfig{Patterns: []string{"/user/{id}", "/products/{id}/push"}},
		Attributes: obi.Attributes{Select: allMetricsBut("client.address", "url.path"), InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"}},
	}, gctx(attributes.GroupHTTPRoutes, &cfg), tracesInput, processEvents)
	// Override eBPF tracer to send some fake data
	tracesInput.Send(newRequest("svc-1", "/user/1234", 200))
	tracesInput.Send(newRequest("svc-1", "/products/3210/push", 200))
	tracesInput.Send(newRequest("svc-1", "/attach", 200))
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	start := time.Now()
	// expect to receive 3 events without any guaranteed order
	events := map[string]collector.MetricRecord{}
	for len(events) < 3 {
		ev := testutil.ReadChannel(t, tc.Records(), testTimeout)
		if ev.Name == "http.server.request.duration" {
			events[ev.Attributes[string(semconv.HTTPRouteKey)]] = ev
		} else {
			t.Logf("skipping event %s", ev.Name)
		}
		if time.Since(start) > testTimeout {
			t.Fatalf("timeout waiting for request.duration event")
		}
	}
	for _, event := range events {
		assert.NotEmpty(t, event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
		delete(event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
		assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
		delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	}
	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.request.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):      "svc-1",
			string(semconv.ServiceNamespaceKey): "ns",
			string(attr.HTTPRequestMethod):      "GET",
			string(attr.HTTPResponseStatusCode): "200",
			string(semconv.HTTPRouteKey):        "/user/{id}",
			string(attr.ServerPort):             "8080",
			string(attr.ServerAddr):             events["/user/{id}"].Attributes["server.address"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "svc-1",
			string(semconv.ServiceNamespaceKey):     "ns",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
		},
		Type:     pmetric.MetricTypeHistogram,
		FloatVal: 2 / float64(time.Second),
		Count:    1,
	}, events["/user/{id}"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.request.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):      "svc-1",
			string(semconv.ServiceNamespaceKey): "ns",
			string(attr.HTTPRequestMethod):      "GET",
			string(attr.HTTPResponseStatusCode): "200",
			string(semconv.HTTPRouteKey):        "/products/{id}/push",
			string(attr.ServerPort):             "8080",
			string(attr.ServerAddr):             events["/products/{id}/push"].Attributes["server.address"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "svc-1",
			string(semconv.ServiceNamespaceKey):     "ns",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
		},
		Type:     pmetric.MetricTypeHistogram,
		FloatVal: 2 / float64(time.Second),
		Count:    1,
	}, events["/products/{id}/push"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.request.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):      "svc-1",
			string(semconv.ServiceNamespaceKey): "ns",
			string(attr.HTTPRequestMethod):      "GET",
			string(attr.HTTPResponseStatusCode): "200",
			string(semconv.HTTPRouteKey):        "/**",
			string(attr.ServerPort):             "8080",
			string(attr.ServerAddr):             events["/**"].Attributes["server.address"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "svc-1",
			string(semconv.ServiceNamespaceKey):     "ns",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
		},
		Type:     pmetric.MetricTypeHistogram,
		FloatVal: 2 / float64(time.Second),
		Count:    1,
	}, events["/**"])

	cancel()
	require.NoError(t, <-done)
}

func TestGRPCPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))

	cfg := otelcfg.MetricsConfig{
		Features:        []string{otelcfg.FeatureApplication},
		MetricsEndpoint: tc.ServerEndpoint, Interval: time.Millisecond,
		ReportersCacheLen: 16,
		TTL:               5 * time.Minute,
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
	}
	gb := newGraphBuilder(&obi.Config{
		Metrics:    cfg,
		Attributes: obi.Attributes{Select: allMetrics, InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"}},
	}, gctx(0, &cfg), tracesInput, processEvents)
	// Override eBPF tracer to send some fake data
	tracesInput.Send(newGRPCRequest("grpc-svc", "/foo/bar", 3))
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	event := testutil.ReadChannel(t, tc.Records(), testTimeout)
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
	delete(event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))

	assert.Equal(t, collector.MetricRecord{
		Name: "rpc.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):       "grpc-svc",
			string(semconv.ServiceNamespaceKey):  "",
			string(semconv.RPCSystemKey):         "grpc",
			string(semconv.RPCGRPCStatusCodeKey): "3",
			string(semconv.RPCMethodKey):         "/foo/bar",
			string(attr.ClientAddr):              "1.1.1.1",
			string(attr.ServerPort):              "8080",
			string(attr.ServerAddr):              event.Attributes["server.address"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "grpc-svc",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
		},
		Type:     pmetric.MetricTypeHistogram,
		FloatVal: 2 / float64(time.Second),
		Count:    1,
	}, event)

	cancel()
	require.NoError(t, <-done)
}

func TestTraceGRPCPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	gb := newGraphBuilder(&obi.Config{
		Traces: otelcfg.TracesConfig{
			TracesEndpoint: tc.ServerEndpoint,
			BatchTimeout:   time.Millisecond, ReportersCacheLen: 16,
			Instrumentations: []string{instrumentations.InstrumentationALL},
		},
		Attributes: obi.Attributes{InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"}},
	}, gctx(0, nil), tracesInput, processEvents)
	// Override eBPF tracer to send some fake data
	tracesInput.Send(newGRPCRequest("svc", "foo.bar", 3))
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchInnerGRPCTraceEvent(t, "in queue", event)
	event = testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchInnerGRPCTraceEvent(t, "processing", event)
	event = testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchGRPCTraceEvent(t, "foo.bar", event)

	cancel()
	require.NoError(t, <-done)
}

func TestBasicPipelineInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	cfg := otelcfg.MetricsConfig{
		Features:        []string{otelcfg.FeatureApplication},
		MetricsEndpoint: tc.ServerEndpoint,
		Interval:        10 * time.Millisecond, ReportersCacheLen: 16,
		TTL: 5 * time.Minute,
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
	}
	gb := newGraphBuilder(&obi.Config{
		Metrics: cfg,
		Attributes: obi.Attributes{
			Select:     allMetrics,
			InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"},
		},
	}, gctx(0, &cfg), tracesInput, processEvents)
	// send some fake data through the traces' input
	tracesInput.Send(newHTTPInfo("PATCH", "/aaa/bbb", "1.1.1.1", 204))
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	event := testutil.ReadChannel(t, tc.Records(), testTimeout)
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
	delete(event.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.request.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(attr.HTTPRequestMethod):      "PATCH",
			string(attr.HTTPResponseStatusCode): "204",
			string(attr.HTTPUrlPath):            "/aaa/bbb",
			string(attr.ClientAddr):             "1.1.1.1",
			string(semconv.ServiceNameKey):      "comm",
			string(semconv.ServiceNamespaceKey): "",
			string(attr.ServerPort):             "8080",
			string(attr.ServerAddr):             event.Attributes["server.address"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "comm",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
		},
		Type:     pmetric.MetricTypeHistogram,
		FloatVal: 1 / float64(time.Second),
		Count:    1,
	}, event)

	cancel()
	require.NoError(t, <-done)
}

func TestTracerPipelineInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	gb := newGraphBuilder(&obi.Config{
		Traces:     otelcfg.TracesConfig{TracesEndpoint: tc.ServerEndpoint, ReportersCacheLen: 16, Instrumentations: []string{instrumentations.InstrumentationALL}},
		Attributes: obi.Attributes{InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"}},
	}, gctx(0, nil), tracesInput, processEvents)
	// Override eBPF tracer to send some fake data
	tracesInput.Send(newHTTPInfo("PATCH", "/aaa/bbb", "1.1.1.1", 204))
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords(), testTimeout)
	matchInfoEvent(t, "PATCH", event)

	cancel()
	require.NoError(t, <-done)
}

func TestSpanAttributeFilterNode(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	// Application pipeline that will let only pass spans whose url.path matches /user/*
	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	cfg := otelcfg.MetricsConfig{
		SDKLogLevel:     "debug",
		Features:        []string{otelcfg.FeatureApplication},
		MetricsEndpoint: tc.ServerEndpoint, Interval: 10 * time.Millisecond,
		ReportersCacheLen: 16,
		TTL:               5 * time.Minute,
		Instrumentations:  []string{instrumentations.InstrumentationALL},
	}
	gb := newGraphBuilder(&obi.Config{
		Metrics: cfg,
		Filters: filter.AttributesConfig{
			Application: map[string]filter.MatchDefinition{"url.path": {Match: "/user/*"}},
		},
		Attributes: obi.Attributes{Select: allMetrics, InstanceID: config.InstanceIDConfig{OverrideHostname: "the-host"}},
	}, gctx(0, &cfg), tracesInput, processEvents)

	// Override eBPF tracer to send some fake data
	tracesInput.Send(newRequest("svc-0", "/products/3210/push", 200))
	tracesInput.Send(newRequest("svc-1", "/user/1234", 201))
	tracesInput.Send(newRequest("svc-2", "/products/3210/push", 202))
	tracesInput.Send(newRequest("svc-3", "/user/4321", 203))

	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	done := pipe.Start(ctx)

	// expect to receive only the records matching the Filters criteria
	events := map[string]map[string]string{}
	for range 10 {
		var event collector.MetricRecord
		test.Eventually(t, testTimeout, func(tt require.TestingT) {
			event = testutil.ReadChannel(t, tc.Records(), testTimeout)
			require.Equal(tt, "http.server.request.duration", event.Name)
		})
		events[event.Attributes["url.path"]] = event.Attributes
	}

	assert.Equal(t, map[string]map[string]string{
		"/user/1234": {
			string(semconv.ServiceNameKey):      "svc-1",
			string(semconv.ServiceNamespaceKey): "ns",
			string(attr.ClientAddr):             "1.1.1.1",
			string(attr.HTTPRequestMethod):      "GET",
			string(attr.HTTPResponseStatusCode): "201",
			string(attr.HTTPUrlPath):            "/user/1234",
			string(attr.ServerPort):             "8080",
			string(attr.ServerAddr):             events["/user/1234"]["server.address"],
		},
		"/user/4321": {
			string(semconv.ServiceNameKey):      "svc-3",
			string(semconv.ServiceNamespaceKey): "ns",
			string(attr.ClientAddr):             "1.1.1.1",
			string(attr.HTTPRequestMethod):      "GET",
			string(attr.HTTPResponseStatusCode): "203",
			string(attr.HTTPUrlPath):            "/user/4321",
			string(attr.ServerPort):             "8080",
			string(attr.ServerAddr):             events["/user/1234"]["server.address"],
		},
	}, events)

	cancel()
	require.NoError(t, <-done)
}

func newRequest(serviceName string, path string, status int) []request.Span {
	return []request.Span{{
		Path:         path,
		Method:       http.MethodGet,
		Peer:         "1.1.1.1",
		Host:         getHostname(),
		HostPort:     8080,
		Status:       status,
		Type:         request.EventTypeHTTP,
		Start:        2,
		RequestStart: 1,
		End:          3,
		Service:      svc.Attrs{HostName: "the-host", UID: svc.UID{Namespace: "ns", Name: serviceName}, SDKLanguage: svc.InstrumentableGolang},
	}}
}

func newRequestWithTiming(svcName string, kind request.EventType, method, path string, status int, goStart, start, end uint64) []request.Span {
	return []request.Span{{
		Path:         path,
		Method:       method,
		Peer:         "2.2.2.2",
		Host:         getHostname(),
		HostPort:     8080,
		Type:         kind,
		Status:       status,
		RequestStart: int64(goStart),
		Start:        int64(start),
		End:          int64(end),
		Service:      svc.Attrs{HostName: "the-host", UID: svc.UID{Name: svcName}, SDKLanguage: svc.InstrumentableGolang},
	}}
}

func newGRPCRequest(svcName string, path string, status int) []request.Span {
	return []request.Span{{
		Path:         path,
		Peer:         "1.1.1.1",
		Host:         "127.0.0.1",
		HostPort:     8080,
		Status:       status,
		Type:         request.EventTypeGRPC,
		Start:        2,
		RequestStart: 1,
		End:          3,
		Service:      svc.Attrs{HostName: "the-host", UID: svc.UID{Name: svcName}, SDKLanguage: svc.InstrumentableGolang},
	}}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

func matchTraceEvent(t require.TestingT, name string, event collector.TraceRecord) {
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))

	assert.NotEmpty(t, event.Attributes["span_id"])
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(attr.HTTPRequestMethod):      "GET",
			string(attr.HTTPResponseStatusCode): "404",
			string(attr.HTTPUrlPath):            "/foo/bar",
			string(attr.ClientAddr):             "1.1.1.1",
			string(attr.ServerAddr):             getHostname(),
			string(attr.ServerPort):             "8080",
			string(attr.HTTPRequestBodySize):    "0",
			string(attr.HTTPResponseBodySize):   "0",
			"span_id":                           event.Attributes["span_id"],
			"parent_span_id":                    event.Attributes["parent_span_id"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "bar-svc",
			string(semconv.ServiceNamespaceKey):     "ns",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
			string(semconv.OTelLibraryNameKey):      "go.opentelemetry.io/obi",
			"overridden":                            "attr",
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func matchInnerTraceEvent(t require.TestingT, name string, event collector.TraceRecord) {
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))

	assert.NotEmpty(t, event.Attributes["span_id"])
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			"span_id":        event.Attributes["span_id"],
			"parent_span_id": event.Attributes["parent_span_id"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "bar-svc",
			string(semconv.ServiceNamespaceKey):     "ns",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
			string(semconv.OTelLibraryNameKey):      "go.opentelemetry.io/obi",
			"overridden":                            "attr",
		},
		Kind: ptrace.SpanKindInternal,
	}, event)
}

func matchGRPCTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))

	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(semconv.RPCSystemKey):         "grpc",
			string(semconv.RPCGRPCStatusCodeKey): "3",
			string(semconv.RPCMethodKey):         "foo.bar",
			string(attr.ClientAddr):              "1.1.1.1",
			string(attr.ServerAddr):              "127.0.0.1",
			string(attr.ServerPort):              "8080",
			"span_id":                            event.Attributes["span_id"],
			"parent_span_id":                     event.Attributes["parent_span_id"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "svc",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
			string(semconv.OTelLibraryNameKey):      "go.opentelemetry.io/obi",
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func matchInnerGRPCTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))

	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			"span_id":        event.Attributes["span_id"],
			"parent_span_id": event.Attributes["parent_span_id"],
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "svc",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
			string(semconv.OTelLibraryNameKey):      "go.opentelemetry.io/obi",
		},
		Kind: ptrace.SpanKindInternal,
	}, event)
}

func matchNestedEvent(t *testing.T, name, method, target, status string, kind ptrace.SpanKind, event collector.TraceRecord) {
	assert.Equal(t, name, event.Name)
	assert.Equal(t, method, event.Attributes[string(attr.HTTPRequestMethod)])
	assert.Equal(t, status, event.Attributes[string(attr.HTTPResponseStatusCode)])
	if kind == ptrace.SpanKindClient {
		assert.Equal(t, target, event.Attributes[string(attr.HTTPUrlFull)])
	} else {
		assert.Equal(t, target, event.Attributes[string(attr.HTTPUrlPath)])
	}
	assert.Equal(t, kind, event.Kind)
}

func newHTTPInfo(method, path, peer string, status int) []request.Span {
	return []request.Span{{
		Type:         1,
		Method:       method,
		Peer:         peer,
		Path:         path,
		Host:         getHostname(),
		HostPort:     8080,
		Status:       status,
		Start:        2,
		RequestStart: 2,
		End:          3,
		Service:      svc.Attrs{HostName: "the-host", UID: svc.UID{Name: "comm"}, SDKLanguage: svc.InstrumentableGolang},
	}}
}

func matchInfoEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.NotEmpty(t, event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))
	delete(event.ResourceAttributes, string(semconv.TelemetrySDKVersionKey))

	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(attr.HTTPRequestMethod):      "PATCH",
			string(attr.HTTPResponseStatusCode): "204",
			string(attr.HTTPUrlPath):            "/aaa/bbb",
			string(attr.ClientAddr):             "1.1.1.1",
			string(attr.ServerAddr):             getHostname(),
			string(attr.ServerPort):             "8080",
			string(attr.HTTPRequestBodySize):    "0",
			string(attr.HTTPResponseBodySize):   "0",
			"span_id":                           event.Attributes["span_id"],
			"parent_span_id":                    "",
		},
		ResourceAttributes: map[string]string{
			string(semconv.HostIDKey):               "host-id",
			string(semconv.HostNameKey):             "the-host",
			string(semconv.ServiceNameKey):          "comm",
			string(semconv.TelemetrySDKLanguageKey): "go",
			string(semconv.TelemetrySDKNameKey):     "opentelemetry-ebpf-instrumentation",
			string(semconv.OSTypeKey):               "linux",
			string(semconv.OTelLibraryNameKey):      "go.opentelemetry.io/obi",
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}
