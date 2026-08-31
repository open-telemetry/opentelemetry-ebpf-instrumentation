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
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
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

func TestRuntimeMetricsReporterRecordsJVMMemoryPoolUsed(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan jvmMetricRecord, 10)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testJVMRuntimeMetricsConsumer(records),
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
		UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		Features: export.FeatureApplicationRuntime,
	}
	reporter.onProcessEvent(&exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 101, Service: service}),
	})

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			Kind:       jvmruntime.JVMMetricMemoryUsed,
			MemoryType: jvmruntime.JVMMemoryTypeHeap,
			PoolName:   "G1 Old Gen",
			GCPhase:    jvmruntime.JVMGCPhaseAfter,
			ValueBytes: 42,
		},
	}})

	record := readJVMMetricRecord(t, records, "jvm.memory.used")
	assert.Equal(t, pmetric.MetricTypeSum, record.Type)
	assert.False(t, record.IsMonotonic)
	assert.Equal(t, int64(42), record.Value)
	assert.Equal(t, "orders", record.ResourceAttrs["service.name"])
	assert.Equal(t, "prod", record.ResourceAttrs["service.namespace"])
	assert.Equal(t, "orders-1", record.ResourceAttrs["service.instance.id"])
	assert.Equal(t, "heap", record.Attrs["jvm.memory.type"])
	assert.Equal(t, "G1 Old Gen", record.Attrs["jvm.memory.pool.name"])
}

func TestRuntimeMetricsReporterRecordsJVMMemoryAsUpDownCounter(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan jvmMetricRecord, 10)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testJVMRuntimeMetricsConsumer(records),
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
		UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		Features: export.FeatureApplicationRuntime,
	}
	reporter.onProcessEvent(&exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 101, Service: service}),
	})

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			Kind:       jvmruntime.JVMMetricMemoryUsed,
			MemoryType: jvmruntime.JVMMemoryTypeHeap,
			PoolName:   "G1 Eden Space",
			ValueBytes: 128,
		},
	}})

	record := readJVMMetricRecord(t, records, "jvm.memory.used")
	assert.Equal(t, pmetric.MetricTypeSum, record.Type)
	assert.False(t, record.IsMonotonic)
	assert.Equal(t, int64(128), record.Value)
	assert.Equal(t, "heap", record.Attrs["jvm.memory.type"])
	assert.Equal(t, "G1 Eden Space", record.Attrs["jvm.memory.pool.name"])
}

func TestRuntimeMetricsReporterRecordsJVMGCDuration(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan jvmMetricRecord, 10)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testJVMRuntimeMetricsConsumer(records),
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
		UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		Features: export.FeatureApplicationRuntime,
	}
	reporter.onProcessEvent(&exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 101, Service: service}),
	})
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			Kind:       jvmruntime.JVMMetricGCDuration,
			GCName:     "G1 Young Generation",
			GCAction:   "end of minor GC",
			DurationNS: 25_000_000,
		},
	}})

	record := readJVMMetricRecord(t, records, "jvm.gc.duration")
	assert.Equal(t, pmetric.MetricTypeHistogram, record.Type)
	assert.Equal(t, int64(1), record.Value)
	assert.InEpsilon(t, 0.025, record.DoubleValue, 0)
	assert.Equal(t, "G1 Young Generation", record.Attrs["jvm.gc.name"])
	assert.Equal(t, "end of minor GC", record.Attrs["jvm.gc.action"])
}

func TestRuntimeMetricsReporterRecordsJVMClassMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan jvmMetricRecord, 10)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testJVMRuntimeMetricsConsumer(records),
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
		UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		ProcPID:  101,
		Features: export.FeatureApplicationRuntime,
	}
	reporter.onProcessEvent(&exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 101, Service: service}),
	})
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				LoadedClassCount:        42,
				TotalLoadedClassCount:   100,
				UnloadedClassCount:      5,
				ThreadCount:             10,
				DaemonThreadCount:       4,
				AvailableProcessorCount: 8,
				ProcessCPUTimeNS:        2_000_000_000,
				RecentCPUUtilization:    0.25,
			},
		},
	}})

	got := readJVMMetricRecords(t, records,
		"jvm.class.loaded",
		"jvm.class.unloaded",
		"jvm.class.count",
		"jvm.thread.count",
		"jvm.thread.count",
		"jvm.cpu.time",
		"jvm.cpu.count",
		"jvm.cpu.recent_utilization",
	)
	assert.Equal(t, int64(100), got["jvm.class.loaded"][0].Value)
	assert.True(t, got["jvm.class.loaded"][0].IsMonotonic)
	assert.Equal(t, int64(5), got["jvm.class.unloaded"][0].Value)
	assert.True(t, got["jvm.class.unloaded"][0].IsMonotonic)
	assert.Equal(t, int64(42), got["jvm.class.count"][0].Value)
	assert.False(t, got["jvm.class.count"][0].IsMonotonic)

	threadCounts := map[string]int64{}
	for _, record := range got["jvm.thread.count"] {
		assert.False(t, record.IsMonotonic)
		threadCounts[record.Attrs["jvm.thread.daemon"]] = record.Value
	}
	assert.Equal(t, map[string]int64{"false": 6, "true": 4}, threadCounts)
	assert.Equal(t, float64(2), got["jvm.cpu.time"][0].DoubleValue)
	assert.True(t, got["jvm.cpu.time"][0].IsMonotonic)
	assert.Equal(t, int64(8), got["jvm.cpu.count"][0].Value)
	assert.False(t, got["jvm.cpu.count"][0].IsMonotonic)
	assert.Equal(t, 0.25, got["jvm.cpu.recent_utilization"][0].DoubleValue)
	assert.Equal(t, pmetric.MetricTypeGauge, got["jvm.cpu.recent_utilization"][0].Type)

	secondService := service
	secondService.ProcPID = 202
	reporter.onProcessEvent(&exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 202, Service: secondService}),
	})
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: secondService,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				TotalLoadedClassCount: 40,
				ProcessCPUTimeNS:      1_000_000_000,
			},
		},
	}})

	readJVMMetricRecordValue(t, records, "jvm.class.loaded", 140)
	readJVMMetricRecordValue(t, records, "jvm.cpu.time", 3)

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				TotalLoadedClassCount: 110,
				ProcessCPUTimeNS:      3_000_000_000,
			},
		},
	}})

	readJVMMetricRecordValue(t, records, "jvm.class.loaded", 150)
	readJVMMetricRecordValue(t, records, "jvm.cpu.time", 4)

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				TotalLoadedClassCount: 10,
				ThreadCount:           4,
				DaemonThreadCount:     10,
				ProcessCPUTimeNS:      100_000_000,
			},
		},
	}})

	// A reset contributes the new process lifetime without removing the
	// existing service aggregate.
	readJVMMetricRecordValue(t, records, "jvm.class.loaded", 160)
	readJVMMetricRecordValue(t, records, "jvm.cpu.time", 4.1)
	readJVMMetricRecordValue(t, records, "jvm.thread.count", 0)
}

func TestRuntimeMetricsReporterRetainsJVMCounterBaselineBeyondTTL(t *testing.T) {
	originalTimeNow := timeNow
	clock := &syncedClock{now: time.Now()}
	timeNow = clock.Now
	t.Cleanup(func() { timeNow = originalTimeNow })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const ttl = time.Minute
	records := make(chan jvmMetricRecord, 100)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               ttl,
		ReportersCacheLen: 10,
		MetricsConsumer:   testJVMRuntimeMetricsConsumer(records),
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
		UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		ProcPID:  101,
		Features: export.FeatureApplicationRuntime,
	}
	file := exec.New(exec.Init{Pid: service.ProcPID, Service: service})
	file.SetRuntimeMetricGeneration(service.ProcPID, 17)
	reporter.onProcessEvent(&exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})

	runtimeSnapshot := func(loaded uint64, cpuTime int64) runtimemetrics.RuntimeMetricSnapshot {
		return runtimemetrics.RuntimeMetricSnapshot{
			Service:    service,
			Generation: 17,
			JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
				RuntimeValues: &jvmruntime.JVMRuntimeValues{
					TotalLoadedClassCount: loaded,
					ProcessCPUTimeNS:      cpuTime,
				},
			},
		}
	}
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		runtimeSnapshot(100, 2_000_000_000),
	})
	readJVMMetricRecordValue(t, records, "jvm.class.loaded", 100)
	readJVMMetricRecordValue(t, records, "jvm.cpu.time", 2)

	clock.Advance(40 * time.Second)
	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			Kind:       jvmruntime.JVMMetricMemoryUsed,
			MemoryType: jvmruntime.JVMMemoryTypeHeap,
			PoolName:   "G1 Old Gen",
			ValueBytes: 42,
		},
	}})
	clock.Advance(40 * time.Second)

	reporter.reportRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		runtimeSnapshot(110, 3_000_000_000),
	})
	readJVMMetricRecordValue(t, records, "jvm.class.loaded", 110)
	readJVMMetricRecordValue(t, records, "jvm.cpu.time", 3)
}

func TestJVMThreadOTELAttributes(t *testing.T) {
	for _, daemon := range []bool{false, true} {
		fields := jvmThreadOTELAttributes(daemon)
		require.Len(t, fields, 1)
		got := fields[0].Get(runtimemetrics.RuntimeMetricSnapshot{})
		assert.Equal(t, "jvm.thread.daemon", string(got.Key))
		assert.Equal(t, daemon, got.Value.AsBool())
	}
}

type jvmMetricRecord struct {
	Name          string
	Type          pmetric.MetricType
	Value         int64
	DoubleValue   float64
	IsMonotonic   bool
	Attrs         map[string]string
	ResourceAttrs map[string]string
}

func testJVMRuntimeMetricsConsumer(out chan<- jvmMetricRecord) consumer.Metrics {
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
					record := jvmMetricRecord{
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
						histogramPoints := metric.Histogram().DataPoints()
						for l := 0; l < histogramPoints.Len(); l++ {
							point := histogramPoints.At(l)
							record.Value = int64(point.Count())
							record.DoubleValue = point.Sum()
							record.Attrs = attrsToMap(point.Attributes())
							out <- record
						}
						continue
					default:
						continue
					}
					for l := 0; l < points.Len(); l++ {
						point := points.At(l)
						if point.ValueType() == pmetric.NumberDataPointValueTypeDouble {
							record.DoubleValue = point.DoubleValue()
						} else {
							record.Value = point.IntValue()
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

func readJVMMetricRecord(t *testing.T, records <-chan jvmMetricRecord, name string) jvmMetricRecord {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case record := <-records:
			if record.Name == name {
				return record
			}
		case <-deadline:
			t.Fatalf("timeout waiting for JVM metric %q", name)
		}
	}
}

func readJVMMetricRecordValue(
	t *testing.T,
	records <-chan jvmMetricRecord,
	name string,
	expected float64,
) jvmMetricRecord {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case record := <-records:
			if record.Name != name {
				continue
			}
			value := float64(record.Value)
			if record.Type == pmetric.MetricTypeGauge || record.DoubleValue != 0 {
				value = record.DoubleValue
			}
			if value == expected {
				return record
			}
		case <-deadline:
			t.Fatalf("timeout waiting for JVM metric %q value %v", name, expected)
		}
	}
}

func readJVMMetricRecords(t *testing.T, records <-chan jvmMetricRecord, names ...string) map[string][]jvmMetricRecord {
	t.Helper()
	wanted := make(map[string]int, len(names))
	for _, name := range names {
		wanted[name]++
	}
	result := make(map[string][]jvmMetricRecord, len(wanted))
	received := 0
	deadline := time.After(2 * time.Second)
	for received < len(names) {
		select {
		case record := <-records:
			if len(result[record.Name]) < wanted[record.Name] {
				result[record.Name] = append(result[record.Name], record)
				received++
			}
		case <-deadline:
			t.Fatalf("timeout waiting for JVM metrics %v", names)
		}
	}
	return result
}

func attrsToMap(attrs pcommon.Map) map[string]string {
	out := make(map[string]string, attrs.Len())
	attrs.Range(func(k string, v pcommon.Value) bool {
		out[k] = v.AsString()
		return true
	})
	return out
}
