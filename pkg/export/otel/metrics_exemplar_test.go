// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestAppMetrics_ExemplarFilterOverridesEnvironment(t *testing.T) {
	tests := []struct {
		configured    string
		env           string
		wantExemplars bool
	}{
		{configured: "always_off", env: "always_on"},
		{configured: "always_on", env: "always_off", wantExemplars: true},
	}

	for _, test := range tests {
		t.Run(test.configured, func(t *testing.T) {
			t.Setenv("OTEL_METRICS_EXEMPLAR_FILTER", test.env)

			ctx := t.Context()
			exemplarCounts := make(chan int, 100)
			metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))
			mcfg := &otelcfg.MetricsConfig{
				Interval:          50 * time.Millisecond,
				TTL:               30 * time.Minute,
				ReportersCacheLen: 10,
				Instrumentations:  []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
				ExemplarFilter:    test.configured,
				MetricsExport:     testServerDurationExemplarsConsumer(exemplarCounts),
			}

			reporter, err := newMetricsReporter(
				ctx,
				&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
				mcfg,
				&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
				&attributes.SelectorConfig{},
				request.UnresolvedNames{},
				metrics,
				processEvents,
			)
			require.NoError(t, err)
			go reporter.reportMetrics(ctx)

			metrics.Send([]request.Span{{
				Service:      svc.Attrs{Features: export.FeatureApplicationRED, UID: svc.UID{Instance: "foo"}},
				Type:         request.EventTypeHTTP,
				Method:       "GET",
				Status:       200,
				RequestStart: 100,
				End:          200,
				TraceID:      trace.TraceID{1},
				SpanID:       trace.SpanID{1},
				TraceFlags:   uint8(trace.FlagsSampled),
			}})

			select {
			case count := <-exemplarCounts:
				require.Equal(t, test.wantExemplars, count > 0)
			case <-time.After(timeout):
				require.Fail(t, "timeout waiting for the HTTP server duration histogram")
			}
		})
	}
}

func testServerDurationExemplarsConsumer(out chan<- int) otelcfg.MetricsExportFunc {
	return testOTLPMetricsExport(func(_ context.Context, md pmetric.Metrics) error {
		for _, rm := range md.ResourceMetrics().All() {
			for _, sm := range rm.ScopeMetrics().All() {
				for _, m := range sm.Metrics().All() {
					if m.Name() != attributes.HTTPServerDuration.OTEL || m.Type() != pmetric.MetricTypeHistogram {
						continue
					}
					for _, point := range m.Histogram().DataPoints().All() {
						out <- point.Exemplars().Len()
					}
				}
			}
		}
		return nil
	})
}
