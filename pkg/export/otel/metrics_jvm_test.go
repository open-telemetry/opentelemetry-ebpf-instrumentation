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
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestJVMRuntimeMetricsReporterRecordsHeapSummary(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	records := make(chan jvmMetricRecord, 10)
	cfg := &otelcfg.MetricsConfig{
		Interval:          20 * time.Millisecond,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		MetricsConsumer:   testJVMRuntimeMetricsConsumer(records),
	}
	reporter, err := newJVMRuntimeMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg,
		&perapp.MetricsConfig{Features: export.FeatureApplicationJVM},
	)
	require.NoError(t, err)
	defer reporter.close()

	reporter.observe(jvmruntime.JVMRuntimeEvent{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
			Features: export.FeatureApplicationJVM,
		},
		Kind:       jvmruntime.JVMMetricBeylaHeapUsed,
		GCPhase:    jvmruntime.JVMGCPhaseAfter,
		ValueBytes: 42,
	})

	record := readJVMMetricRecord(t, records, "beyla.jvm.heap.used")
	assert.Equal(t, int64(42), record.Value)
	assert.Equal(t, "orders", record.ResourceAttrs["service.name"])
	assert.Equal(t, "prod", record.ResourceAttrs["service.namespace"])
	assert.Equal(t, "orders-1", record.ResourceAttrs["service.instance.id"])
	assert.Equal(t, "after", record.Attrs["jvm.gc.phase"])
}

type jvmMetricRecord struct {
	Name          string
	Value         int64
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
					if metric.Type() != pmetric.MetricTypeGauge {
						continue
					}
					points := metric.Gauge().DataPoints()
					for l := 0; l < points.Len(); l++ {
						point := points.At(l)
						out <- jvmMetricRecord{
							Name:          metric.Name(),
							Value:         point.IntValue(),
							Attrs:         attrsToMap(point.Attributes()),
							ResourceAttrs: resourceAttrs,
						}
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

func attrsToMap(attrs pcommon.Map) map[string]string {
	out := make(map[string]string, attrs.Len())
	attrs.Range(func(k string, v pcommon.Value) bool {
		out[k] = v.AsString()
		return true
	})
	return out
}
