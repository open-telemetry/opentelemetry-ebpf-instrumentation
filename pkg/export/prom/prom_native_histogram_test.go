// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// TestNativeHistogramSchemaAppliedToExportedMetrics is an integration test that
// creates a full Prometheus reporter with a custom NativeHistogramConfig, sends an
// HTTP span, and verifies that the gathered histogram DTO uses the expected schema.
func TestNativeHistogramSchemaAppliedToExportedMetrics(t *testing.T) {
	for _, tc := range []struct {
		name           string
		nhCfg          NativeHistogramConfig
		expectedSchema int32
	}{
		{
			name:           "default config produces schema 3",
			nhCfg:          DefaultNativeHistogramConfig,
			expectedSchema: 3,
		},
		{
			name:           "BucketFactor=4.0 produces schema -1",
			nhCfg:          NativeHistogramConfig{BucketFactor: 4.0, MaxBucketNumber: 100, MinResetDuration: time.Hour},
			expectedSchema: -1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			ctx := t.Context()
			promInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))

			exporter, err := PrometheusEndpoint(
				&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
				&PrometheusConfig{
					Registry:         registry,
					Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
					NativeHistogram:  tc.nhCfg,
					ExemplarFilter:   "always_off",
				},
				&perapp.MetricsConfig{Features: export.FeatureApplicationRED},
				&attributes.SelectorConfig{},
				request.UnresolvedNames{},
				promInput,
				processEvents,
				nil,
			)(ctx)
			require.NoError(t, err)
			go exporter(ctx)

			svcAttrs := svc.Attrs{
				Features: export.FeatureApplicationRED,
				UID:      svc.UID{Name: "test-svc", Instance: "inst-1"},
			}
			promInput.Send([]request.Span{{
				Type:         request.EventTypeHTTP,
				RequestStart: 0,
				End:          100_000_000,
				Service:      svcAttrs,
			}})
			awaitSpanProcessing()

			mfs, err := registry.Gather()
			require.NoError(t, err)

			var schema *int32
			for _, mf := range mfs {
				if mf.GetName() != attributes.HTTPServerDuration.Prom {
					continue
				}
				for _, m := range mf.GetMetric() {
					s := m.GetHistogram().GetSchema()
					schema = &s
				}
			}
			require.NotNil(t, schema, "HTTP server duration metric not found in registry")
			assert.Equal(t, tc.expectedSchema, *schema)
		})
	}
}
