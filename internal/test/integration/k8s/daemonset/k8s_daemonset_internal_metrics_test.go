// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// prometheusHostPort is the host-mapped port of the suite's Prometheus
// (02-prometheus-otelscrape.yml), which scrapes the otelcol's exporter.
const prometheusHostPort = "localhost:39090"

// The OBI daemonset runs with internal_metrics.exporter=otel
// (06-obi-daemonset.yml), so its internal metrics reach the suite otelcol,
// which fans them out to both the weaver tap and its Prometheus exporter
// (03-otelcol-weaver.yml). obi.kube.cache.forward.lag — the in-process kube
// informer forward lag, a Float64Histogram in seconds — is therefore validated
// by the weaver live-check; this asserts the same metric also lands in
// Prometheus (as obi_kube_cache_forward_lag_seconds_*), giving it deterministic
// coverage on both paths.
func TestInternalMetrics_ForwardLag(t *testing.T) {
	feat := features.New("OBI exports the kube informer forward-lag internal metric").
		Assess("obi.kube.cache.forward.lag reaches Prometheus via the otelcol",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				pq := promtest.Client{HostPort: prometheusHostPort}
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					results, err := pq.Query(`{__name__=~"obi_kube_cache_forward_lag.*"}`)
					require.NoError(ct, err)
					require.NotEmpty(ct, results,
						"obi.kube.cache.forward.lag was not exported to Prometheus by the otelcol")
				}, testTimeout, time.Second)
				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
