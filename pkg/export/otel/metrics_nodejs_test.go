// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type nodejsMetricRecord struct {
	Name          string
	Type          pmetric.MetricType
	Value         float64
	Count         uint64
	IsMonotonic   bool
	Attrs         map[string]string
	ResourceAttrs map[string]string
}

func testNodejsRuntimeMetricsConsumer(out chan<- nodejsMetricRecord) consumer.Metrics {
	c, err := consumer.NewMetrics(func(_ context.Context, md pmetric.Metrics) error {
		rm := md.ResourceMetrics()
		for i := 0; i < rm.Len(); i++ {
			resourceAttrs := attrsToMap(rm.At(i).Resource().Attributes())
			sm := rm.At(i).ScopeMetrics()
			for j := 0; j < sm.Len(); j++ {
				metrics := sm.At(j).Metrics()
				for k := 0; k < metrics.Len(); k++ {
					metric := metrics.At(k)
					var points pmetric.NumberDataPointSlice
					record := nodejsMetricRecord{
						Name:          metric.Name(),
						Type:          metric.Type(),
						ResourceAttrs: resourceAttrs,
					}
					switch metric.Type() {
					case pmetric.MetricTypeGauge:
						points = metric.Gauge().DataPoints()
					case pmetric.MetricTypeSum:
						sum := metric.Sum()
						record.IsMonotonic = sum.IsMonotonic()
						points = sum.DataPoints()
					case pmetric.MetricTypeHistogram:
						histPoints := metric.Histogram().DataPoints()
						for l := 0; l < histPoints.Len(); l++ {
							point := histPoints.At(l)
							record.Value = point.Sum()
							record.Count = point.Count()
							record.Attrs = attrsToMap(point.Attributes())
							out <- record
						}
						continue
					default:
						continue
					}
					for l := 0; l < points.Len(); l++ {
						point := points.At(l)
						if point.ValueType() == pmetric.NumberDataPointValueTypeInt {
							record.Value = float64(point.IntValue())
						} else {
							record.Value = point.DoubleValue()
						}
						record.Attrs = attrsToMap(point.Attributes())
						out <- record
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	return c
}

func readNodejsMetricRecord(t *testing.T, records <-chan nodejsMetricRecord, name, state string) nodejsMetricRecord {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case record := <-records:
			if record.Name != name {
				continue
			}
			if state != "" && record.Attrs["nodejs.eventloop.state"] != state {
				continue
			}
			return record
		case <-deadline:
			t.Fatalf("timeout waiting for nodejs metric %q (state %q)", name, state)
		}
	}
}

func TestRuntimeMetricsReporterRecordsNodejsEventLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan nodejsMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testNodejsRuntimeMetricsConsumer(records),
	}
	reporter, err := newRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	defer reporter.close()

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders-node", Namespace: "prod", Instance: "orders-node-1"},
			Features: export.FeatureApplicationRuntime,
			ProcPID:  app.PID(1055),
		},
		PID: 55,
		Nodejs: &runtimemetrics.NodejsRuntimeMetricSnapshot{
			NodejsEventLoopValues: nodejsruntime.NodejsEventLoopValues{
				ELUIdleNs:   2_000_000_000, // 2 s
				ELUActiveNs: 1_000_000_000, // 1 s
				DelayP99Ns:  5_000_000,     // 5 ms
				DelayCount:  42,
			},
		},
	}})

	idle := readNodejsMetricRecord(t, records, attributes.NodejsEventLoopTime.OTEL, "idle")
	assert.Equal(t, pmetric.MetricTypeSum, idle.Type)
	assert.True(t, idle.IsMonotonic)
	assert.InDelta(t, 2.0, idle.Value, 1e-9)
	assert.Equal(t, "orders-node", idle.ResourceAttrs["service.name"])

	active := readNodejsMetricRecord(t, records, attributes.NodejsEventLoopTime.OTEL, "active")
	assert.InDelta(t, 1.0, active.Value, 1e-9)

	utilization := readNodejsMetricRecord(t, records, attributes.NodejsEventLoopUtilization.OTEL, "")
	assert.Equal(t, pmetric.MetricTypeGauge, utilization.Type)
	assert.InDelta(t, 1.0/3.0, utilization.Value, 1e-9)

	p99 := readNodejsMetricRecord(t, records, attributes.NodejsEventLoopDelayP99.OTEL, "")
	assert.Equal(t, pmetric.MetricTypeGauge, p99.Type)
	assert.InDelta(t, 0.005, p99.Value, 1e-9)
}

func TestNodejsDelayGaugesSkipEmptyWindows(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan nodejsMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testNodejsRuntimeMetricsConsumer(records),
	}
	reporter, err := newRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	defer reporter.close()

	service := svc.Attrs{
		UID:      svc.UID{Name: "orders-node", Namespace: "prod", Instance: "orders-node-1"},
		Features: export.FeatureApplicationRuntime,
	}
	snapshot := func(idleNs, activeNs, p99Ns, count uint64) []runtimemetrics.RuntimeMetricSnapshot {
		return []runtimemetrics.RuntimeMetricSnapshot{{
			Service: service,
			PID:     55,
			Nodejs: &runtimemetrics.NodejsRuntimeMetricSnapshot{
				NodejsEventLoopValues: nodejsruntime.NodejsEventLoopValues{
					ELUIdleNs:   idleNs,
					ELUActiveNs: activeNs,
					DelayP99Ns:  p99Ns,
					DelayCount:  count,
				},
			},
		}}
	}

	reporter.reportRuntimeMetrics(snapshot(2_000_000_000, 1_000_000_000, 5_000_000, 42))
	p99 := readNodejsMetricRecord(t, records, attributes.NodejsEventLoopDelayP99.OTEL, "")
	assert.InDelta(t, 0.005, p99.Value, 1e-9)

	// A fully-blocked interval reports an empty histogram: the delay gauges
	// must keep the previous window's values instead of dropping to zero.
	reporter.reportRuntimeMetrics(snapshot(3_000_000_000, 1_500_000_000, 0, 0))

	// wait until the second snapshot is visible through the counter path
	// (readNodejsMetricRecord's internal deadline bounds this loop) ...
	for {
		idle := readNodejsMetricRecord(t, records, attributes.NodejsEventLoopTime.OTEL, "idle")
		if idle.Value > 2.5 {
			break
		}
	}
	// ... then the delay gauge must still export the previous window
	p99 = readNodejsMetricRecord(t, records, attributes.NodejsEventLoopDelayP99.OTEL, "")
	assert.InDelta(t, 0.005, p99.Value, 1e-9)
}

func TestRuntimeMetricsReporterRecordsV8GCDuration(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan nodejsMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testNodejsRuntimeMetricsConsumer(records),
	}
	reporter, err := newRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	defer reporter.close()

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders-node", Namespace: "prod", Instance: "orders-node-1"},
			Features: export.FeatureApplicationRuntime,
		},
		PID: 55,
		NodejsGC: &runtimemetrics.NodejsGCSnapshot{
			GCType:     nodejsruntime.NodejsGCTypeMajor,
			DurationNs: 350_000_000, // 350 ms
		},
	}})

	gc := readNodejsMetricRecord(t, records, attributes.V8JSGCDuration.OTEL, "")
	assert.Equal(t, pmetric.MetricTypeHistogram, gc.Type)
	assert.Equal(t, uint64(1), gc.Count)
	assert.InDelta(t, 0.35, gc.Value, 1e-9)
	assert.Equal(t, "major", gc.Attrs["v8js.gc.type"])
	assert.Equal(t, "orders-node", gc.ResourceAttrs["service.name"])
}

func TestRuntimeMetricsReporterRecordsV8HeapSpaces(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan nodejsMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testNodejsRuntimeMetricsConsumer(records),
	}
	reporter, err := newRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	defer reporter.close()

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders-node", Namespace: "prod", Instance: "orders-node-1"},
			Features: export.FeatureApplicationRuntime,
		},
		PID: 55,
		NodejsHeapSpace: &runtimemetrics.NodejsHeapSpaceSnapshot{
			SpaceName: "old_space",
			NodejsHeapSpaceValues: nodejsruntime.NodejsHeapSpaceValues{
				SpaceSize:          200 << 20,
				SpaceUsedSize:      150 << 20,
				SpaceAvailableSize: 30 << 20,
				PhysicalSpaceSize:  200 << 20,
			},
		},
	}})

	expected := map[string]float64{
		attributes.V8JSMemoryHeapLimit.OTEL:              float64(uint64(200 << 20)),
		attributes.V8JSMemoryHeapUsed.OTEL:               float64(uint64(150 << 20)),
		attributes.V8JSMemoryHeapSpaceAvailableSize.OTEL: float64(uint64(30 << 20)),
		attributes.V8JSMemoryHeapSpacePhysicalSize.OTEL:  float64(uint64(200 << 20)),
	}
	for name, value := range expected {
		record := readNodejsMetricRecord(t, records, name, "")
		assert.Equal(t, pmetric.MetricTypeSum, record.Type, name)
		assert.False(t, record.IsMonotonic, name)
		assert.InDelta(t, value, record.Value, 1e-9, name)
		assert.Equal(t, "old_space", record.Attrs["v8js.heap.space.name"], name)
	}
}

func TestRuntimeMetricsReporterRecordsV8ResourceActive(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan nodejsMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testNodejsRuntimeMetricsConsumer(records),
	}
	reporter, err := newRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	defer reporter.close()

	service := svc.Attrs{
		UID:      svc.UID{Name: "orders-node", Namespace: "prod", Instance: "orders-node-1"},
		Features: export.FeatureApplicationRuntime,
	}
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		PID:     55,
		NodejsResource: &runtimemetrics.NodejsResourceSnapshot{
			ResourceType: "Timeout",
			Count:        5,
		},
	}})

	timeout := readNodejsMetricRecord(t, records, attributes.V8JSResourceActive.OTEL, "")
	assert.Equal(t, pmetric.MetricTypeGauge, timeout.Type)
	assert.InDelta(t, 5.0, timeout.Value, 1e-9)
	assert.Equal(t, "Timeout", timeout.Attrs["v8js.resource.type"])
	assert.Equal(t, "orders-node", timeout.ResourceAttrs["service.name"])

	// the vanished-type explicit zero must be recorded as a real zero, not
	// skipped: a skipped record would leave the gauge frozen at 5
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		PID:     55,
		NodejsResource: &runtimemetrics.NodejsResourceSnapshot{
			ResourceType: "Timeout",
			Count:        0,
		},
	}})

	for {
		record := readNodejsMetricRecord(t, records, attributes.V8JSResourceActive.OTEL, "")
		if record.Value == 5.0 {
			continue // earlier export cycle, keep draining
		}
		assert.InDelta(t, 0.0, record.Value, 1e-9)
		break
	}
}

func TestRuntimeMetricsReporterDropsV8ServiceWithoutRuntimeFeature(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan nodejsMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testNodejsRuntimeMetricsConsumer(records),
	}
	reporter, err := newRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	defer reporter.close()

	service := svc.Attrs{
		UID:      svc.UID{Name: "orders-node", Namespace: "prod", Instance: "orders-node-1"},
		Features: export.FeatureApplicationRED,
	}
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		{Service: service, PID: 55, NodejsGC: &runtimemetrics.NodejsGCSnapshot{
			GCType: nodejsruntime.NodejsGCTypeMajor, DurationNs: 1000,
		}},
		{Service: service, PID: 55, NodejsHeapSpace: &runtimemetrics.NodejsHeapSpaceSnapshot{
			SpaceName: "old_space",
		}},
		{Service: service, PID: 55, NodejsResource: &runtimemetrics.NodejsResourceSnapshot{
			ResourceType: "Timeout", Count: 5,
		}},
	})

	select {
	case record := <-records:
		t.Fatalf("expected no v8 metrics for a service without the runtime feature, got %q", record.Name)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRuntimeMetricsReporterDropsNodejsServiceWithoutRuntimeFeature(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan nodejsMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testNodejsRuntimeMetricsConsumer(records),
	}
	reporter, err := newRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	defer reporter.close()

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders-node", Namespace: "prod", Instance: "orders-node-1"},
			Features: export.FeatureApplicationRED,
		},
		PID: 55,
		Nodejs: &runtimemetrics.NodejsRuntimeMetricSnapshot{
			NodejsEventLoopValues: nodejsruntime.NodejsEventLoopValues{
				ELUIdleNs:   2_000_000_000,
				ELUActiveNs: 1_000_000_000,
				DelayP99Ns:  5_000_000,
				DelayCount:  42,
			},
		},
	}})

	select {
	case record := <-records:
		t.Fatalf("expected no metrics for a service without the runtime feature, got %q", record.Name)
	case <-time.After(200 * time.Millisecond):
	}
}
