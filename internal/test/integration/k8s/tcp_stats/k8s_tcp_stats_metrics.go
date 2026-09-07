// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcpstats // import "go.opentelemetry.io/obi/internal/test/integration/k8s/tcp_stats"

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/kube"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
)

const (
	testTimeout        = 5 * time.Minute
	prometheusHostPort = "localhost:39090"
	pingerPodName      = "internal-pinger-tcp-stats"

	// A cardinality-exploded metric makes each Prometheus query cost hundreds of
	// milliseconds, so a sub-second poll only piles up in-flight requests.
	pollInterval = time.Second
)

func FeatureTCPStats() features.Feature {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   pingerPodName,
			TargetURL: "http://testserver:8080/iping",
		},
	}
	return features.New("tcp stats").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("emits tcp stat metrics", testTCPStatsEmitted).
		Assess("decorates tcp io metrics with kubernetes metadata", testTCPStatsIODecoration).
		Feature()
}

func testTCPStatsEmitted(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query("obi_stat_tcp_io_bytes_total")
		assert.NoError(ct, err)
		assert.NotEmpty(ct, results)
	}, testTimeout, pollInterval)
	return ctx
}

// testTCPStatsIODecoration pins the query to the flow the pinger generates.
// obi.stat.tcp.io is selected with every attribute in this suite, including the
// ports, so the metric carries a series per connection: asserting the label set
// of an arbitrary member would sample unrelated flows — node-sourced ones that
// legitimately have no namespace, or traffic to the CNI gateway that has no
// destination workload.
func testTCPStatsIODecoration(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_io_bytes_total{` +
			`k8s_cluster_name="my-kube",` +
			`k8s_src_name="` + pingerPodName + `",` +
			`k8s_dst_name=~"testserver.*"` +
			`}`)
		assert.NoError(ct, err)
		assert.NotEmpty(ct, results)

		for _, res := range results {
			metric := res.Metric
			assert.NotEmpty(ct, metric["k8s_src_namespace"])
			assert.NotEmpty(ct, metric["k8s_src_owner_name"])
			assert.NotEmpty(ct, metric["k8s_src_owner_type"])
			assert.NotEmpty(ct, metric["k8s_src_node_name"])
			assert.NotEmpty(ct, metric["k8s_dst_namespace"])
			assert.Contains(ct, []string{"receive", "transmit"}, metric["network_io_direction"])
		}
	}, testTimeout, pollInterval)
	return ctx
}
