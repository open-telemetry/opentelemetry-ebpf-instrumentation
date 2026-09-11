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
	failPingerPodName  = "internal-pinger-tcp-stats-fail"
	closedPort         = "19999"

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
			// obi.stat.tcp.rtt is reported from the tcp_close probe, so a
			// keep-alive client would report nothing until pod teardown.
			Env: map[string]string{"DISABLE_KEEPALIVES": "true"},
		},
	}
	// Nothing listens on this pod's own closed port, so every request is refused
	// by the kernel and feeds obi.stat.tcp.failed.connections.
	failPinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   failPingerPodName,
			TargetURL: "http://127.0.0.1:" + closedPort + "/iping",
		},
	}
	// obi.stat.tcp.retransmits is not asserted: retransmissions require packet
	// loss, which the docker-compose stat suite injects with netem on the client
	// container. This suite has no equivalent injection, so an assertion on that
	// metric would only wait for the full timeout.
	return features.New("tcp stats").
		Setup(pinger.Deploy()).
		Setup(failPinger.Deploy()).
		Teardown(pinger.Delete()).
		Teardown(failPinger.Delete()).
		Assess("emits tcp stat metrics", testTCPStatsEmitted).
		Assess("decorates tcp io metrics with kubernetes metadata", testTCPStatsIODecoration).
		Assess("emits tcp rtt as a histogram", testTCPStatsRTT).
		Assess("emits tcp failed connections", testTCPStatsFailedConnections).
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

func testTCPStatsIODecoration(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(pingerFlow("obi_stat_tcp_io_bytes_total"))
		assert.NoError(ct, err)
		assert.NotEmpty(ct, results)

		assertPingerFlowDecoration(ct, results)
		for _, res := range results {
			assert.Contains(ct, []string{"receive", "transmit"}, res.Metric["network_io_direction"])
		}
	}, testTimeout, pollInterval)
	return ctx
}

func testTCPStatsRTT(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		counts, err := pq.Query(pingerFlow("obi_stat_tcp_rtt_seconds_count") + " > 0")
		assert.NoError(ct, err)
		assert.NotEmpty(ct, counts)
		assertPingerFlowDecoration(ct, counts)

		sums, err := pq.Query(pingerFlow("obi_stat_tcp_rtt_seconds_sum") + " > 0")
		assert.NoError(ct, err)
		assert.NotEmpty(ct, sums)

		buckets, err := pq.Query("count(" + pingerFlow("obi_stat_tcp_rtt_seconds_bucket") + ")")
		assert.NoError(ct, err)
		assert.NotEmpty(ct, buckets)
	}, testTimeout, pollInterval)
	return ctx
}

// testTCPStatsFailedConnections pins the query to the port the fail pinger
// dials. That connection is refused over loopback, whose addresses carry no
// kubernetes metadata, so port and handshake role are what identify the series.
func testTCPStatsFailedConnections(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_failed_connections_total{` +
			`dst_port="` + closedPort + `",` +
			`network_tcp_handshake_role="client",` +
			`reason="refused"` +
			`} > 0`)
		assert.NoError(ct, err)
		assert.NotEmpty(ct, results)
	}, testTimeout, pollInterval)
	return ctx
}

func assertPingerFlowDecoration(ct *assert.CollectT, results []promtest.Result) {
	for _, res := range results {
		metric := res.Metric
		assert.NotEmpty(ct, metric["k8s_src_namespace"])
		assert.NotEmpty(ct, metric["k8s_src_owner_name"])
		assert.NotEmpty(ct, metric["k8s_src_owner_type"])
		assert.NotEmpty(ct, metric["k8s_src_node_name"])
		assert.NotEmpty(ct, metric["k8s_dst_namespace"])
		assert.Equal(ct, "testserver", metric["k8s_dst_owner_name"])
		assert.Equal(ct, "Service", metric["k8s_dst_owner_type"])
	}
}

// pingerFlow pins a query to the flow the pinger generates. The obi.stat.tcp.*
// metrics are selected with every attribute in this suite, including the ports,
// so each metric carries a series per connection: asserting the label set of an
// arbitrary member would sample unrelated flows — node-sourced ones that
// legitimately have no namespace, or traffic to the CNI gateway that has no
// destination workload.
func pingerFlow(metric string) string {
	return metric + `{` +
		`k8s_cluster_name="my-kube",` +
		`k8s_src_name="` + pingerPodName + `",` +
		`k8s_dst_name=~"testserver.*"` +
		`}`
}
