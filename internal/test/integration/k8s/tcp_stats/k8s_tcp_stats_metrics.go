// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcpstats // import "go.opentelemetry.io/obi/internal/test/integration/k8s/tcp_stats"

import (
	"context"
	"sort"
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
)

func FeatureTCPStats() features.Feature {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger-tcp-stats",
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
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)
	return ctx
}

func testTCPStatsIODecoration(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_io_bytes_total{k8s_cluster_name="my-kube"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		metric := results[0].Metric
		logLabels(t, "obi_stat_tcp_io_bytes_total", metric)
		assert.NotEmpty(ct, metric["k8s_src_namespace"])
		assert.NotEmpty(ct, metric["k8s_src_name"])
		assert.NotEmpty(ct, metric["k8s_src_owner_name"])
		assert.NotEmpty(ct, metric["k8s_src_owner_type"])
		assert.NotEmpty(ct, metric["k8s_src_node_name"])
		assert.NotEmpty(ct, metric["k8s_dst_name"])
		assert.NotEmpty(ct, metric["k8s_dst_namespace"])
		assert.Contains(ct, []string{"receive", "transmit"}, metric["network_io_direction"])
	}, testTimeout, 100*time.Millisecond)
	return ctx
}

// logLabels records the label set actually present on a series, so a failing
// assertion can be diagnosed from the test output without another CI round.
func logLabels(t *testing.T, metric string, labels map[string]string) {
	t.Helper()

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%s label %s=%q", metric, k, labels[k])
	}
}
