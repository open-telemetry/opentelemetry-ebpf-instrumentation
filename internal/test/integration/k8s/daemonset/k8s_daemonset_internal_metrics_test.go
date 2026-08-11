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

// The OBI daemonset exports its internal metrics via the otel exporter
// (06-obi-daemonset.yml), which the suite otelcol re-exports to Prometheus
// (03-otelcol-weaver.yml). This asserts obi.kube.cache.forward.lag — the
// in-process kube informer forward lag — reaches Prometheus, matched by name so
// the histogram suffix is not load-bearing.
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
