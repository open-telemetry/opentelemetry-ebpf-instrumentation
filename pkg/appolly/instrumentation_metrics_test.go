// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestProtocolMetricsEnablement(t *testing.T) {
	for _, test := range []struct {
		name        string
		v2          bool
		httpEnabled bool
		wantHTTP    bool
	}{
		{name: "v2 disabled", v2: true},
		{name: "v2 enabled", v2: true, httpEnabled: true, wantHTTP: true},
		{name: "v1 disabled", wantHTTP: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cfg *obi.Config
			var err error
			if test.v2 {
				ext, parseErr := schema.ParseReceiverYAML([]byte(fmt.Sprintf(`
version: '2.0'
metrics:
  features: [application_span_otel, application_service_graph]
instrumentation:
  http:
    enabled:
      traces: true
      metrics: %t
`, test.httpEnabled)))
				require.NoError(t, parseErr)
				cfg, err = convert.V2ToRuntime(ext)
			} else {
				cfg, err = obi.LoadConfig(strings.NewReader(`
metrics:
  features: [application_span_otel, application_service_graph]
otel_metrics_export:
  instrumentations: [grpc]
prometheus_export:
  instrumentations: [grpc]
`))
			}
			require.NoError(t, err)
			cfg.NameResolver = nil
			var tracesMu, metricsMu sync.Mutex
			var traceBatches []ptrace.Traces
			var metricBatches []pmetric.Metrics
			cfg.Traces.TracesExport = func(_ context.Context, data []byte) error {
				request := ptraceotlp.NewExportRequest()
				if err := request.UnmarshalProto(data); err != nil {
					return err
				}
				tracesMu.Lock()
				traceBatches = append(traceBatches, request.Traces())
				tracesMu.Unlock()
				return nil
			}
			cfg.Traces.BatchTimeout = 10 * time.Millisecond
			cfg.OTELMetrics.MetricsExport = func(_ context.Context, data []byte) error {
				request := pmetricotlp.NewExportRequest()
				if err := request.UnmarshalProto(data); err != nil {
					return err
				}
				metricsMu.Lock()
				metricBatches = append(metricBatches, request.Metrics())
				metricsMu.Unlock()
				return nil
			}
			getTraces := func() []ptrace.Traces {
				tracesMu.Lock()
				defer tracesMu.Unlock()
				return append([]ptrace.Traces(nil), traceBatches...)
			}
			getMetrics := func() []pmetric.Metrics {
				metricsMu.Lock()
				defer metricsMu.Unlock()
				return append([]pmetric.Metrics(nil), metricBatches...)
			}
			cfg.OTELMetrics.Interval = 10 * time.Millisecond
			cfg.Prometheus.Registry = prometheus.NewRegistry()
			ctxInfo := gctx(0, &cfg.OTELMetrics)
			ctxInfo.Prometheus = &connector.PrometheusManager{}
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var pipe *Instrumenter
			if test.v2 {
				selection := instrumentations.NewInstrumentationSelection(cfg.OTELMetrics.Instrumentations)
				pipe, err = BuildWithProtocolMetricSelection(ctx, cfg, ctxInfo, input, processEvents, nil, &selection)
			} else {
				pipe, err = Build(ctx, cfg, ctxInfo, input, processEvents, nil)
			}
			require.NoError(t, err)
			done := pipe.Start(ctx)

			spans := append(newRequest("http-service", "/http", 200), newGRPCRequest("grpc-service", "/grpc", 0)...)
			for i := range spans {
				spans[i].Service.Features = cfg.Metrics.Features
			}
			input.Send(spans)

			metricNames := []attributes.Name{attributes.SpanMetricsCallsOTel, attributes.ServiceGraphServer}
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				assert.True(ct, traceServices(getTraces())["http-service"])
				assert.True(ct, traceServices(getTraces())["grpc-service"])
				got := metricServices(getMetrics())
				families, gatherErr := cfg.Prometheus.Registry.Gather()
				assert.NoError(ct, gatherErr)
				for _, name := range metricNames {
					assert.Contains(ct, got[name.OTEL], "grpc-service")
					var samples int
					for _, family := range families {
						if family.GetName() == name.Prom {
							samples = len(family.Metric)
						}
					}
					wantSamples := 1
					if test.wantHTTP {
						wantSamples++
						assert.Contains(ct, got[name.OTEL], "http-service")
					}
					assert.Equal(ct, wantSamples, samples, name.Prom)
				}
			}, gateTestTimeout, 10*time.Millisecond)

			cancel()
			require.NoError(t, <-done)
			got := metricServices(getMetrics())
			for _, name := range metricNames {
				assert.Equal(t, test.wantHTTP, got[name.OTEL]["http-service"], name.OTEL)
			}
		})
	}
}

func traceServices(batches []ptrace.Traces) map[string]bool {
	services := map[string]bool{}
	for _, batch := range batches {
		resources := batch.ResourceSpans()
		for i := range resources.Len() {
			resource := resources.At(i)
			service, _ := resource.Resource().Attributes().Get("service.name")
			scopes := resource.ScopeSpans()
			for j := range scopes.Len() {
				spans := scopes.At(j).Spans()
				for k := range spans.Len() {
					if spans.At(k).Kind() == ptrace.SpanKindServer {
						services[service.Str()] = true
					}
				}
			}
		}
	}
	return services
}

func metricServices(batches []pmetric.Metrics) map[string]map[string]bool {
	services := map[string]map[string]bool{}
	for _, batch := range batches {
		resources := batch.ResourceMetrics()
		for i := range resources.Len() {
			resource := resources.At(i)
			service, _ := resource.Resource().Attributes().Get("service.name")
			scopes := resource.ScopeMetrics()
			for j := range scopes.Len() {
				metrics := scopes.At(j).Metrics()
				for k := range metrics.Len() {
					name := metrics.At(k).Name()
					if services[name] == nil {
						services[name] = map[string]bool{}
					}
					services[name][service.Str()] = true
				}
			}
		}
	}
	return services
}
