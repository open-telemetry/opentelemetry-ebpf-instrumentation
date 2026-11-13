// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/collector"
	"go.opentelemetry.io/obi/collector/internal"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

// A v2 receiver config cannot configure internal metrics, so they go to the Collector service
// telemetry. A v1 receiver config keeps reporting them only when configured.
func TestCollectorReceiverInternalMetrics(t *testing.T) {
	for _, tc := range []struct {
		name     string
		config   func(t *testing.T) component.Config
		reported bool
	}{
		{name: "v2", config: v2ReceiverConfig, reported: true},
		{name: "v1", config: func(*testing.T) component.Config { return exceptionReceiverConfig() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reporters := make(chan imetrics.Reporter, 1)
			internal.SetRunOBIForTest(t, func(ctx context.Context, _ *obi.Config, info *global.ContextInfo, _ *instrumentations.InstrumentationSelection, _ ...instrumenter.Option) error {
				reporters <- info.Metrics
				<-ctx.Done()
				return nil
			})

			telemetry := componenttest.NewTelemetry()
			t.Cleanup(func() { require.NoError(t, telemetry.Shutdown(context.Background())) })

			factory := collector.NewFactory()
			settings := receivertest.NewNopSettings(factory.Type())
			settings.ID = component.MustNewIDWithName("obi", "internal-metrics-"+tc.name)
			settings.TelemetrySettings = telemetry.NewTelemetrySettings()

			receiver, err := factory.CreateMetrics(t.Context(), settings, tc.config(t), consumertest.NewNop())
			require.NoError(t, err)
			require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
			t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.Background())) })

			reporter := <-reporters
			reporter.QueueBufferUtilization("traces", 0.5)

			_, err = telemetry.GetMetric(attr.VendorPrefix + ".queue.capacity.ratio")
			if tc.reported {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Receivers with different IDs run separate OBI instances on the same Collector telemetry, so
// each one's internal metrics carry its receiver ID as a scope attribute.
func TestCollectorReceiverInternalMetricsPerReceiver(t *testing.T) {
	reporters := make(chan imetrics.Reporter, 2)
	internal.SetRunOBIForTest(t, func(ctx context.Context, _ *obi.Config, info *global.ContextInfo, _ *instrumentations.InstrumentationSelection, _ ...instrumenter.Option) error {
		reporters <- info.Metrics
		<-ctx.Done()
		return nil
	})

	telemetry := componenttest.NewTelemetry()
	t.Cleanup(func() { require.NoError(t, telemetry.Shutdown(context.Background())) })

	factory := collector.NewFactory()
	ratios := map[string]float64{}
	for _, name := range []string{"internal-metrics-a", "internal-metrics-b"} {
		settings := receivertest.NewNopSettings(factory.Type())
		settings.ID = component.MustNewIDWithName("obi", name)
		settings.TelemetrySettings = telemetry.NewTelemetrySettings()

		receiver, err := factory.CreateMetrics(t.Context(), settings, v2ReceiverConfig(t), consumertest.NewNop())
		require.NoError(t, err)
		require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
		t.Cleanup(func() { require.NoError(t, receiver.Shutdown(context.Background())) })

		ratio := float64(len(ratios)+1) / 10
		(<-reporters).QueueBufferUtilization("traces", ratio)
		ratios[settings.ID.String()] = ratio
	}

	var rm metricdata.ResourceMetrics
	require.NoError(t, telemetry.Reader.Collect(t.Context(), &rm))

	reported := map[string]float64{}
	for _, sm := range rm.ScopeMetrics {
		id, ok := sm.Scope.Attributes.Value("otelcol.component.id")
		if !ok {
			continue
		}
		for _, m := range sm.Metrics {
			if m.Name != attr.VendorPrefix+".queue.capacity.ratio" {
				continue
			}
			gauge, ok := m.Data.(metricdata.Gauge[float64])
			require.True(t, ok)
			require.Len(t, gauge.DataPoints, 1)
			reported[id.AsString()] = gauge.DataPoints[0].Value
		}
	}
	assert.Equal(t, ratios, reported)
}

func v2ReceiverConfig(t *testing.T) component.Config {
	t.Helper()

	cfg := collector.NewFactory().CreateDefaultConfig()
	require.NoError(t, confmap.NewFromStringMap(map[string]any{
		"version": "2.0",
	}).Unmarshal(cfg))
	return cfg
}
