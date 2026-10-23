// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	netebpf "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/shutdown"
	statsebpf "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const noPeriodicExport = time.Hour

func shutdownTestConfig(records chan collector.MetricRecord, cacheLen int) *otelcfg.MetricsConfig {
	return &otelcfg.MetricsConfig{
		Interval:          noPeriodicExport,
		TTL:               time.Hour,
		ReportersCacheLen: cacheLen,
		Instrumentations:  []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
		MetricsExport:     testMetricsConsumer(records),
	}
}

func httpClientSpan(service svc.Attrs) request.Span {
	return request.Span{
		Service: service, Type: request.EventTypeHTTPClient,
		Method: "GET", Path: "/", RequestStart: 100, End: 200, Status: 200,
	}
}

func TestFailingConstructorReleasesTheSharedExporter(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()

	collectorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer collectorServer.Close()

	mcfg := &otelcfg.MetricsConfig{
		MetricsEndpoint:  collectorServer.URL,
		Protocol:         otelcfg.ProtocolHTTPProtobuf,
		Interval:         noPeriodicExport,
		TTL:              time.Hour,
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}
	instancer := &otelcfg.MetricsExporterInstancer{Cfg: mcfg}

	remainingUser, err := instancer.Instantiate(t.Context())
	require.NoError(t, err)
	require.NoError(t, remainingUser.Export(t.Context(), &metricdata.ResourceMetrics{}))

	_, err = newRuntimeMetricsReporter(
		t.Context(),
		&global.ContextInfo{OTELMetricsExporter: instancer},
		mcfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](),
		msg.NewQueue[exec.ProcessEvent](),
	)
	require.Error(t, err, "a zero reporters cache length fails after the exporter is instantiated")

	require.NoError(t, remainingUser.Shutdown(t.Context()))
	assert.Error(t, remainingUser.Export(t.Context(), &metricdata.ResourceMetrics{}),
		"the real exporter is shut down once the remaining user releases it")
}

func TestAppMetrics_FinalExportOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 10)
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(0))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(0))
	reporter, err := newMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		spans,
		processEvents,
	)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		reporter.reportMetrics(ctx)
		close(done)
	}()

	service := svc.Attrs{Features: export.FeatureApplicationRED, UID: svc.UID{Name: "svc", Instance: "svc-1"}}
	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 1, Service: service}),
	})
	spans.Send([]request.Span{httpClientSpan(service)})
	spans.Send([]request.Span{})

	select {
	case record := <-records:
		require.Failf(t, "unexpected export before shutdown", "%+v", record)
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "reportMetrics did not finish")
	}

	exported := readMetricsByName(t, records, time.Second, attributes.HTTPClientDuration.OTEL, TargetInfo)
	require.Len(t, exported, 2)
	for _, record := range exported {
		if record.Name == attributes.HTTPClientDuration.OTEL {
			assert.Equal(t, "svc-1", record.ResourceAttributes["service.instance.id"])
			assert.Equal(t, 1, record.Count)
		} else {
			assert.Contains(t, slices.Collect(maps.Values(record.Attributes)), "svc-1")
		}
	}
}

func TestAppMetrics_EvictionExportsTheLastPoints(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 1)
	reporter, err := newMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		msg.NewQueue[[]request.Span](),
		msg.NewQueue[exec.ProcessEvent](),
	)
	require.NoError(t, err)

	evicted := svc.Attrs{Features: export.FeatureApplicationRED, UID: svc.UID{Name: "evicted", Instance: "evicted-1"}}
	other := svc.Attrs{Features: export.FeatureApplicationRED, UID: svc.UID{Name: "other", Instance: "other-1"}}
	reporter.onSpan([]request.Span{httpClientSpan(evicted)})
	reporter.onSpan([]request.Span{httpClientSpan(other)})

	exported := readMetricsByName(t, records, 5*time.Second, attributes.HTTPClientDuration.OTEL)
	require.Len(t, exported, 1)
	assert.Equal(t, "evicted-1", exported[0].ResourceAttributes["service.instance.id"])
	assert.Equal(t, 1, exported[0].Count)
}

func TestSvcGraphMetrics_FinalExportOnShutdown(t *testing.T) {
	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 10)
	reporter, err := newSvcGraphMetricsReporter(
		t.Context(),
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		msg.NewQueue[[]request.Span](),
		msg.NewQueue[exec.ProcessEvent](),
	)
	require.NoError(t, err)

	client := svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Name: "client", Instance: "client-1"}}
	reporter.onSpan([]request.Span{{
		Service: client, Type: request.EventTypeHTTPClient,
		Peer: "client-host", Host: "server-host", HostName: "server",
		Path: "/", RequestStart: 100, End: 200, Status: 200,
	}})
	reporter.close()

	exported := readMetricsByName(t, records, 5*time.Second, attributes.ServiceGraphTotal.OTEL)
	require.Len(t, exported, 1)
	assert.Equal(t, int64(1), exported[0].IntVal)
}

func TestRuntimeMetrics_FinalExportOnShutdown(t *testing.T) {
	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 10)
	reporter, err := newRuntimeMetricsReporter(
		t.Context(),
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](),
		msg.NewQueue[exec.ProcessEvent](),
	)
	require.NoError(t, err)

	service := svc.Attrs{
		Features:    export.FeatureApplicationRuntime,
		UID:         svc.UID{Name: "orders", Instance: "orders-1"},
		SDKLanguage: svc.InstrumentableGolang,
	}
	reporter.onProcessEvent(&exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 101, Service: service}),
	})
	goroutines := int64(7)
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		PID:     101,
		Service: service,
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{GoroutineCount: &goroutines},
	}})
	reporter.close()

	exported := readMetricsByName(t, records, 5*time.Second, attributes.GoRuntimeGoroutineCount.OTEL)
	require.Len(t, exported, 1)
	assert.Equal(t, goroutines, exported[0].IntVal)
}

func runUntilInputCloses(t *testing.T, do func(context.Context), closeInput func()) {
	done := make(chan struct{})
	go func() {
		do(t.Context())
		close(done)
	}()
	closeInput()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "exporter did not finish")
	}
}

func TestNetMetrics_FinalExportOnShutdown(t *testing.T) {
	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 10)
	input := msg.NewQueue[[]*netebpf.Record](msg.ChannelBufferLen(10))
	exporter, err := newMetricsExporter(t.Context(),
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		&NetMetricsConfig{
			SelectorCfg: &attributes.SelectorConfig{},
			Metrics:     mcfg,
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureNetwork},
		}, input)
	require.NoError(t, err)

	runUntilInputCloses(t, exporter.Do, func() {
		input.Send([]*netebpf.Record{{Metrics: netebpf.NetFlowMetrics{Bytes: 100, Packets: 1}}})
		input.Close()
	})

	exported := readMetricsByName(t, records, time.Second, attributes.NetworkFlow.OTEL)
	require.Len(t, exported, 1)
	assert.Equal(t, int64(100), exported[0].IntVal)
}

func TestStatMetrics_FinalExportOnShutdown(t *testing.T) {
	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 10)
	input := msg.NewQueue[[]*statsebpf.Stat](msg.ChannelBufferLen(10))
	exporter, err := newStatMetricsExporter(t.Context(),
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		&StatMetricsConfig{
			SelectorCfg: &attributes.SelectorConfig{},
			Metrics:     mcfg,
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStatsTCPRetransmits},
		}, input)
	require.NoError(t, err)

	runUntilInputCloses(t, exporter.Do, func() {
		input.Send([]*statsebpf.Stat{{TCPRetransmit: true}})
		input.Close()
	})

	exported := readMetricsByName(t, records, time.Second, attributes.StatTCPRetransmits.OTEL)
	require.Len(t, exported, 1)
	assert.Equal(t, int64(1), exported[0].IntVal)
}

func TestInternalMetrics_FinalExportOnShutdown(t *testing.T) {
	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 10)
	ctx, cancel := context.WithCancel(t.Context())
	reporter, err := NewInternalMetricsReporter(ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&imetrics.InternalMetricsConfig{},
	)
	require.NoError(t, err)

	cancel()
	reporter.TracerFlush(3)
	require.NoError(t, reporter.Shutdown(t.Context()))

	tracerFlushes := attributes.NewInternalMetrics(attr.VendorPrefix).TracerFlushes.OTEL
	exported := readMetricsByName(t, records, 5*time.Second, tracerFlushes)
	require.Len(t, exported, 1)
	assert.Equal(t, 1, exported[0].Count)
}

func closeDiscardingExports[T any](closeReporter func(), records <-chan T) {
	closed := make(chan struct{})
	go func() {
		for {
			select {
			case <-records:
			case <-closed:
				return
			}
		}
	}()
	closeReporter()
	close(closed)
}

func newTestMetricsReporter(t *testing.T, ctx context.Context, mcfg *otelcfg.MetricsConfig) *MetricsReporter {
	reporter, err := newMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		msg.NewQueue[[]request.Span](),
		msg.NewQueue[exec.ProcessEvent](),
	)
	require.NoError(t, err)
	return reporter
}

func TestAppMetrics_FinalExportIsBoundedByTheShutdownBudget(t *testing.T) {
	const budget = 200 * time.Millisecond
	ctx, signal := context.WithCancel(t.Context())
	defer signal()
	ctx, cancelBudget := shutdown.WithBudget(ctx, budget)
	defer cancelBudget()

	mcfg := shutdownTestConfig(nil, 10)
	mcfg.MetricsExport = func(ctx context.Context, _ pmetric.Metrics) error {
		<-ctx.Done()
		return ctx.Err()
	}
	reporter := newTestMetricsReporter(t, ctx, mcfg)
	service := svc.Attrs{Features: export.FeatureApplicationRED, UID: svc.UID{Name: "svc", Instance: "svc-1"}}
	reporter.onSpan([]request.Span{httpClientSpan(service)})

	signal()
	closed := runUntilDoneT(reporter.close)
	select {
	case <-closed:
	case <-time.After(budget + 5*time.Second):
		require.FailNow(t, "the final export to an unreachable endpoint overran the shutdown budget")
	}
}

func TestAppMetrics_EvictionAfterTheSignalExportsTheLastPoints(t *testing.T) {
	ctx, signal := context.WithCancel(t.Context())
	ctx, cancelBudget := shutdown.WithBudget(ctx, 5*time.Second)
	defer cancelBudget()

	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 1)
	consume := mcfg.MetricsExport
	mcfg.MetricsExport = func(ctx context.Context, md pmetric.Metrics) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return consume(ctx, md)
	}
	reporter := newTestMetricsReporter(t, ctx, mcfg)

	signal()
	evicted := svc.Attrs{Features: export.FeatureApplicationRED, UID: svc.UID{Name: "evicted", Instance: "evicted-1"}}
	other := svc.Attrs{Features: export.FeatureApplicationRED, UID: svc.UID{Name: "other", Instance: "other-1"}}
	reporter.onSpan([]request.Span{httpClientSpan(evicted)})
	reporter.onSpan([]request.Span{httpClientSpan(other)})

	exported := readMetricsByName(t, records, 5*time.Second, attributes.HTTPClientDuration.OTEL)
	require.Len(t, exported, 1)
	assert.Equal(t, "evicted-1", exported[0].ResourceAttributes["service.instance.id"])
}

func runUntilDoneT(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}
