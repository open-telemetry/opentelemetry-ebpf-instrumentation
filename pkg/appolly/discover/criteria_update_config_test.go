// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestCriteriaUpdaterV2ExporterHeaders(t *testing.T) {
	const traceHeaders = "headers: [{name: authorization, value: trace-token}]"
	const metricHeaders = "headers: [{name: authorization, value: metric-token}]"
	for _, protocol := range []string{"otlp_http", "otlp_grpc"} {
		t.Run(protocol, func(t *testing.T) {
			load := func(port int, traces, metrics string) *obi.Config {
				t.Helper()
				doc, _, err := schema.ParseStandaloneYAML([]byte(fmt.Sprintf(`
file_format: "1.0"
tracer_provider:
  processors:
    - batch:
        exporter:
          %s:
            endpoint: https://traces.example:4318
            %s
meter_provider:
  readers:
    - periodic:
        exporter:
          %s:
            endpoint: https://metrics.example:4318
            %s
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
      rules:
        - action: include
          match:
            process:
              open_ports: %d
`, protocol, traces, protocol, metrics, port)))
				require.NoError(t, err)
				cfg, err := convert.DocumentToRuntime(doc)
				require.NoError(t, err)
				require.NoError(t, cfg.ValidateStatic())
				return cfg
			}

			initial := load(8080, traceHeaders, metricHeaders)
			updater := discover.NewCriteriaUpdater(initial)
			matcher := &discover.Matcher{
				Log: slog.Default(), Criteria: discover.FindingCriteria(initial),
				ProcessHistory:  map[app.PID]discover.ProcessMatch{},
				Output:          msg.NewQueue[[]discover.Event[discover.ProcessMatch]](),
				CriteriaUpdates: updater.Updates(),
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan struct{})
			go func() { defer close(done); matcher.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				testutil.ReadChannel(t, done, time.Second)
			})

			// Each conversion creates new closures, even for an unchanged file.
			for _, port := range []int{8080, 9090} {
				next := load(port, traceHeaders, metricHeaders)
				require.NoError(t, updater.Update(ctx, next))
				include, _ := updater.Updates().Current()
				require.Len(t, include, 1)
				require.True(t, include[0].GetOpenPorts().Matches(port))

				for _, cfg := range []*obi.Config{initial, next} {
					traceHeaders, metricHeaders := map[string]string{}, map[string]string{}
					require.NotNil(t, cfg.Traces.InjectHeaders)
					require.NotNil(t, cfg.OTELMetrics.InjectHeaders)
					cfg.Traces.InjectHeaders(traceHeaders)
					cfg.OTELMetrics.InjectHeaders(metricHeaders)
					require.Equal(t, map[string]string{"authorization": "trace-token"}, traceHeaders)
					require.Equal(t, map[string]string{"authorization": "metric-token"}, metricHeaders)
				}
			}

			for _, tc := range []struct {
				name    string
				traces  string
				metrics string
			}{
				{name: "changed trace header", traces: "headers: [{name: authorization, value: rotated-trace-token}]", metrics: metricHeaders},
				{name: "changed metric header", traces: traceHeaders, metrics: "headers: [{name: authorization, value: rotated-metric-token}]"},
				{name: "removed trace header", traces: "headers: []", metrics: metricHeaders},
				{name: "removed metric header", traces: traceHeaders, metrics: "headers: []"},
				{name: "added trace header", traces: traceHeaders + "\n            headers_list: tenant=new-tenant", metrics: metricHeaders},
				{name: "added metric header", traces: traceHeaders, metrics: metricHeaders + "\n            headers_list: tenant=new-tenant"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// Reject header-only edits and edits that also change selection.
					for _, port := range []int{9090, 7070} {
						next := load(port, tc.traces, tc.metrics)
						require.ErrorContains(t, updater.Update(ctx, next), "restart OBI")
						include, _ := updater.Updates().Current()
						require.Len(t, include, 1)
						require.True(t, include[0].GetOpenPorts().Matches(9090))
						require.False(t, include[0].GetOpenPorts().Matches(7070))
					}
				})
			}

			// Different declarations with the same effective headers are compatible.
			next := load(6060,
				traceHeaders+"\n            headers_list: authorization=overridden",
				"headers_list: authorization=metric-token")
			require.NoError(t, updater.Update(ctx, next))
			include, _ := updater.Updates().Current()
			require.True(t, include[0].GetOpenPorts().Matches(6060))
		})
	}
}
