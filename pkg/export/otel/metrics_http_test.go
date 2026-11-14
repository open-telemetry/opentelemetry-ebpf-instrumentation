// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pmetric"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestHTTPActiveRequestsExport(t *testing.T) {
	for _, selectServer := range []bool{false, true} {
		t.Run(map[bool]string{false: "default attributes", true: "server address"}[selectServer], func(t *testing.T) {
			selection := &attributes.SelectorConfig{}
			if selectServer {
				selection.SelectionCfg = attributes.Selection{attributes.HTTPServerActiveRequests.Section: {
					Include: []string{"http.request.method", "url.scheme", "server.address"},
				}}
			}

			fakeMux.Lock()
			defer fakeMux.Unlock()
			now := time.Now()
			originalClock := timeNow
			timeNow = func() time.Time { return now }
			defer func() { timeNow = originalClock }()

			records := make(chan collector.MetricRecord, 100)
			var sums []bool

			cfg := &otelcfg.MetricsConfig{
				Interval:          time.Hour,
				TTL:               time.Minute,
				ReportersCacheLen: 1,
				Instrumentations:  []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
				MetricsExport: testOTLPMetricsExport(func(_ context.Context, md pmetric.Metrics) error {
					for _, rm := range md.ResourceMetrics().All() {
						for _, sm := range rm.ScopeMetrics().All() {
							for _, metric := range sm.Metrics().All() {
								if metric.Name() == attributes.HTTPServerActiveRequests.OTEL {
									sums = append(sums, metric.Sum().IsMonotonic())
								}
							}
						}
					}

					collector.VisitMetricRecords(md, func(record collector.MetricRecord) { records <- record })

					return nil
				}),
			}

			reporter, err := newMetricsReporter(t.Context(),
				&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
				cfg, &perapp.GlobalMetricsConfig{Features: export.FeatureHTTPServerActiveRequests},
				selection, request.UnresolvedNames{},
				msg.NewQueue[[]request.Span](), msg.NewQueue[exec.ProcessEvent]())
			require.NoError(t, err)
			defer reporter.close()

			span := request.Span{
				Type:             request.EventTypeHTTP,
				Method:           "GET",
				Statement:        "https" + request.SchemeHostSeparator,
				RequestAuthority: "api.example.com:8443",
				Route:            "/ignored",
				Status:           200,
				Service: svc.Attrs{
					UID:      svc.UID{Name: "server", Instance: "one"},
					Features: export.FeatureHTTPServerActiveRequests,
				},
			}

			for _, step := range []struct {
				delta int64
				want  int64
			}{
				{1, 1},
				{1, 2},
				{-1, 1},
				{-1, 0},
			} {
				reporter.onHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: step.delta}})

				m := reporter.httpActiveMetrics[span.Service.UID]
				require.NotNil(t, m)

				// Expiry and pressure on the ordinary reporter cache must preserve active requests.
				now = now.Add(2 * cfg.TTL)
				if step.want > 0 {
					reporter.expireHTTPActiveRequests(t.Context())
					require.Same(t, m, reporter.httpActiveMetrics[span.Service.UID])
				}

				_, err = reporter.reporters.For(&svc.Attrs{UID: svc.UID{Name: "other"}})
				require.NoError(t, err)
				require.NoError(t, m.provider.ForceFlush(t.Context()))

				record := testutil.ReadChannel(t, records, time.Second)
				assert.Equal(t, attributes.HTTPServerActiveRequests.OTEL, record.Name)
				assert.Equal(t, "{request}", record.Unit)
				assert.Equal(t, pmetric.MetricTypeSum, record.Type)
				assert.Equal(t, step.want, record.IntVal)
				want := map[string]string{"http.request.method": "GET", "url.scheme": "https"}
				if selectServer {
					want["server.address"] = "api.example.com"
				}

				assert.Equal(t, want, record.Attributes)
				assert.Equal(t, "server", record.ResourceAttributes["service.name"])
			}

			assert.Equal(t, []bool{false, false, false, false}, sums)
			reporter.expireHTTPActiveRequests(t.Context())
			assert.Empty(t, reporter.httpActiveMetrics)

			// A stale end must not create a new negative series after expiry.
			reporter.onHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: -1}})
			assert.Empty(t, reporter.httpActiveMetrics)
		})
	}
}

func TestHTTPActiveRequestsSelection(t *testing.T) {
	for _, tt := range []struct {
		name     string
		features export.Features
		protocol instrumentations.Instrumentation
		want     bool
	}{
		{"explicit", export.FeatureHTTPServerActiveRequests, instrumentations.InstrumentationHTTP, true},
		{"application", export.FeatureApplicationRED, instrumentations.InstrumentationHTTP, false},
		{"all", export.FeatureAll, instrumentations.InstrumentationHTTP, false},
		{"http disabled", export.FeatureHTTPServerActiveRequests, instrumentations.InstrumentationGRPC, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			queue := msg.NewQueue[[]request.HTTPServerRequestDelta](msg.ChannelBufferLen(1))
			cfg := &otelcfg.MetricsConfig{
				Interval:          time.Hour,
				TTL:               time.Minute,
				ReportersCacheLen: 1,
				Instrumentations:  []instrumentations.Instrumentation{tt.protocol},
				MetricsExport:     testMetricsConsumer(make(chan collector.MetricRecord, 20)),
			}

			reporter, err := newMetricsReporter(t.Context(), &global.ContextInfo{
				AppO11y:             global.AppO11y{HTTPServerRequests: queue},
				OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg},
			}, cfg, &perapp.GlobalMetricsConfig{Features: tt.features}, &attributes.SelectorConfig{},
				request.UnresolvedNames{}, msg.NewQueue[[]request.Span](), msg.NewQueue[exec.ProcessEvent]())
			require.NoError(t, err)
			defer reporter.close()

			assert.Equal(t, tt.want, reporter.httpServerRequests != nil)

			span := request.Span{
				Service: svc.Attrs{
					UID:      svc.UID{Name: "server"},
					Features: export.FeatureHTTPServerActiveRequests,
				},
			}
			span.Service.ExportModes = services.NewExportModes()

			reporter.onHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: 1}})
			assert.Empty(t, reporter.httpActiveMetrics)

			span.Service.ExportModes = services.ExportModeUnset
			span.Service.Features = export.FeatureApplicationRED

			reporter.onHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: 1}})
			assert.Empty(t, reporter.httpActiveMetrics)
		})
	}
}
