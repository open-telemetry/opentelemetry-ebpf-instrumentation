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
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestHTTPActiveRequestsMetric(t *testing.T) {
	for _, selectServer := range []bool{false, true} {
		t.Run(map[bool]string{false: "default attributes", true: "server attributes"}[selectServer], func(t *testing.T) {
			cfg := &attributes.SelectorConfig{}
			if selectServer {
				cfg.SelectionCfg = attributes.Selection{attributes.HTTPServerActiveRequests.Section: {
					Include: []string{"http.request.method", "url.scheme", "server.address", "server.port"},
				}}
			}

			selector, err := attributes.NewAttrSelector(0, cfg)
			require.NoError(t, err)

			getters := attributes.PrometheusGetters(request.SpanPromGettersForHTTP(request.UnresolvedNames{}),
				selector.For(attributes.HTTPServerActiveRequests))
			now := time.Now()
			metric := newHTTPActiveRequestsMetric(getters, func() time.Time { return now }, time.Minute)
			reporter := &metricsReporter{httpActiveRequests: metric}
			registry := prometheus.NewRegistry()
			require.NoError(t, registry.Register(metric))

			span := request.Span{
				Type:             request.EventTypeHTTP,
				Method:           "GET",
				Statement:        "http" + request.SchemeHostSeparator,
				RequestAuthority: "api.example.com:8080",
				Host:             "127.0.0.1",
				HostPort:         8080,
				Route:            "/ignored",
				Status:           200,
				Service:          svc.Attrs{Features: export.FeatureHTTPServerActiveRequests},
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
				reporter.observeHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: step.delta}})
				if step.want > 0 {
					now = now.Add(2 * time.Minute)
				}

				families, err := registry.Gather()
				require.NoError(t, err)
				require.Len(t, families, 1)
				assert.Equal(t, attributes.HTTPServerActiveRequests.Prom, families[0].GetName())
				require.Len(t, families[0].Metric, 1)

				point := families[0].Metric[0]
				assert.InDelta(t, float64(step.want), point.GetGauge().GetValue(), 0)

				labels := map[string]string{}
				for _, pair := range point.Label {
					labels[pair.GetName()] = pair.GetValue()
				}

				want := map[string]string{attr.HTTPRequestMethod.Prom(): "GET", attr.HTTPURLScheme.Prom(): "http"}
				if selectServer {
					want[attr.ServerAddr.Prom()] = "api.example.com"
					want[attr.ServerPort.Prom()] = "8080"
				}

				assert.Equal(t, want, labels)
			}

			now = now.Add(2 * time.Minute)
			families, err := registry.Gather()
			require.NoError(t, err)
			assert.Empty(t, families)

			reporter.observeHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: -1}})
			assert.Empty(t, metric.series)
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
			server, _ := newPrometheusTestServer(t)
			queue := msg.NewQueue[[]request.HTTPServerRequestDelta](msg.ChannelBufferLen(1))
			cfg := &PrometheusConfig{
				Port:                        server.Port,
				Path:                        "/metrics",
				TTL:                         time.Minute,
				SpanMetricsServiceCacheSize: 10,
				Instrumentations:            []instrumentations.Instrumentation{tt.protocol},
			}

			reporter, err := newReporter(t.Context(), &global.ContextInfo{
				Prometheus: server.Manager,
				AppO11y:    global.AppO11y{HTTPServerRequests: queue},
			}, cfg,
				&perapp.GlobalMetricsConfig{Features: tt.features}, &attributes.SelectorConfig{}, request.UnresolvedNames{},
				msg.NewQueue[[]request.Span](), msg.NewQueue[exec.ProcessEvent](), nil)
			require.NoError(t, err)

			assert.Equal(t, tt.want, reporter.httpServerRequests != nil)
			assert.Equal(t, tt.want, reporter.httpActiveRequests != nil)
			if !tt.want {
				return
			}

			span := request.Span{
				Service: svc.Attrs{
					Features:    export.FeatureHTTPServerActiveRequests,
					ExportModes: services.NewExportModes(),
				},
			}

			reporter.observeHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: 1}})
			assert.Empty(t, reporter.httpActiveRequests.series)

			span.Service.ExportModes = services.ExportModeUnset
			span.Service.Features = export.FeatureApplicationRED

			reporter.observeHTTPServerRequests([]request.HTTPServerRequestDelta{{Span: span, Delta: 1}})
			assert.Empty(t, reporter.httpActiveRequests.series)
		})
	}
}
