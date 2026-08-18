// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func newNodejsTestReporter(t *testing.T, registry *prometheus.Registry) *metricsReporter {
	t.Helper()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
		nil,
	)
	require.NoError(t, err)
	return reporter
}

func nodejsTestSnapshot(features export.Features, values nodejsruntime.NodejsEventLoopValues) runtimemetrics.RuntimeMetricSnapshot {
	return runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
			Features: features,
			ProcPID:  app.PID(1055),
		},
		PID:    app.PID(55),
		Nodejs: &runtimemetrics.NodejsRuntimeMetricSnapshot{NodejsEventLoopValues: values},
	}
}

func nodejsServiceLabels() map[string]string {
	return map[string]string{
		"service_name":        "orders",
		"service_namespace":   "prod",
		"service_instance_id": "orders-1",
	}
}

func nodejsStateLabels(state string) map[string]string {
	labels := nodejsServiceLabels()
	labels["nodejs_eventloop_state"] = state
	return labels
}

func TestRuntimeMetricsReporterRecordsNodejsEventLoop(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newNodejsTestReporter(t, registry)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		nodejsTestSnapshot(export.FeatureApplicationRuntime, nodejsruntime.NodejsEventLoopValues{
			ELUIdleNs:   10_000_000_000,
			ELUActiveNs: 5_000_000_000,
			DelayMaxNs:  200_000_000,
			DelayP99Ns:  150_000_000,
			DelayCount:  42,
		}),
	})

	idle := gatheredMetric(t, registry, "nodejs_eventloop_time_seconds_total", nodejsStateLabels("idle"))
	require.NotNil(t, idle)
	assert.InEpsilon(t, 10.0, idle.GetCounter().GetValue(), 1e-9)

	active := gatheredMetric(t, registry, "nodejs_eventloop_time_seconds_total", nodejsStateLabels("active"))
	require.NotNil(t, active)
	assert.InEpsilon(t, 5.0, active.GetCounter().GetValue(), 1e-9)

	utilization := gatheredMetric(t, registry, "nodejs_eventloop_utilization_ratio", nodejsServiceLabels())
	require.NotNil(t, utilization)
	assert.InEpsilon(t, 5.0/15.0, utilization.GetGauge().GetValue(), 1e-9)

	delayMax := gatheredMetric(t, registry, "nodejs_eventloop_delay_max_seconds", nodejsServiceLabels())
	require.NotNil(t, delayMax)
	assert.InEpsilon(t, 0.2, delayMax.GetGauge().GetValue(), 1e-9)
}

func TestRuntimeMetricsReporterKeepsNodejsDelayOnEmptyWindow(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newNodejsTestReporter(t, registry)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		nodejsTestSnapshot(export.FeatureApplicationRuntime, nodejsruntime.NodejsEventLoopValues{
			ELUIdleNs:   10_000_000_000,
			ELUActiveNs: 5_000_000_000,
			DelayMaxNs:  200_000_000,
			DelayCount:  42,
		}),
	})
	// fully blocked interval: no delay samples, delay fields are zero
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		nodejsTestSnapshot(export.FeatureApplicationRuntime, nodejsruntime.NodejsEventLoopValues{
			ELUIdleNs:   10_000_000_000,
			ELUActiveNs: 7_000_000_000,
			DelayCount:  0,
		}),
	})

	delayMax := gatheredMetric(t, registry, "nodejs_eventloop_delay_max_seconds", nodejsServiceLabels())
	require.NotNil(t, delayMax)
	assert.InEpsilon(t, 0.2, delayMax.GetGauge().GetValue(), 1e-9,
		"an empty delay window must keep the previous value, not record zeros")
}

func TestRuntimeMetricsReporterDropsNodejsServiceWithoutRuntimeFeature(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newNodejsTestReporter(t, registry)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{
		nodejsTestSnapshot(export.FeatureApplicationRED, nodejsruntime.NodejsEventLoopValues{
			ELUIdleNs:   10_000_000_000,
			ELUActiveNs: 5_000_000_000,
			DelayCount:  42,
		}),
	})

	assert.Nil(t, gatheredMetric(t, registry, "nodejs_eventloop_time_seconds_total", nodejsStateLabels("idle")))
	assert.Nil(t, gatheredMetric(t, registry, "nodejs_eventloop_utilization_ratio", nodejsServiceLabels()))
}

func testNodejsCollector(clock expire.Clock, ttl time.Duration) nodejsRuntimeMetricsCollector {
	return nodejsRuntimeMetricsCollector{
		prev:           expire.NewExpiryMap[*nodejsPrevELU](clock, ttl),
		clock:          clock,
		lastExpiration: clock(),
		ttl:            ttl,
	}
}

func TestNodejsELUDeltasArePerKey(t *testing.T) {
	c := testNodejsCollector(time.Now, time.Minute)

	idle, active := c.eluDeltas("svc-1|55", 100_000_000_000, 50_000_000_000)
	assert.Equal(t, uint64(100_000_000_000), idle)
	assert.Equal(t, uint64(50_000_000_000), active)

	// second reading for the same pid: deltas
	idle, active = c.eluDeltas("svc-1|55", 130_000_000_000, 70_000_000_000)
	assert.Equal(t, uint64(30_000_000_000), idle)
	assert.Equal(t, uint64(20_000_000_000), active)

	// a different pid of the same service does not share state
	idle, active = c.eluDeltas("svc-1|56", 10_000_000_000, 5_000_000_000)
	assert.Equal(t, uint64(10_000_000_000), idle)
	assert.Equal(t, uint64(5_000_000_000), active)

	// counter reset (restarted loop) counts the full current value
	idle, active = c.eluDeltas("svc-1|55", 7_000_000_000, 3_000_000_000)
	assert.Equal(t, uint64(7_000_000_000), idle)
	assert.Equal(t, uint64(3_000_000_000), active)
}

func TestNodejsELUPrevStateExpires(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	c := testNodejsCollector(clock, time.Minute)

	c.eluDeltas("svc-1|55", 10_000_000_000, 5_000_000_000)

	// past the TTL the delta state is swept: the next sample counts as a
	// first sample (full value) instead of a delta against stale state
	now = now.Add(2 * time.Minute)
	idle, active := c.eluDeltas("svc-1|55", 13_000_000_000, 7_000_000_000)
	assert.Equal(t, uint64(13_000_000_000), idle)
	assert.Equal(t, uint64(7_000_000_000), active)
}
