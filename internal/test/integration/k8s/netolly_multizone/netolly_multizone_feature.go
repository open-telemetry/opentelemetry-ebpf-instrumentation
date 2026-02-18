// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/internal/test/integration/k8s/netolly_multizone"

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

const (
	testTimeout        = 3 * time.Minute
	prometheusHostPort = "localhost:39090"
)

func FeatureMultizoneNetworkFlows() features.Feature {
	return features.New("Multizone Network flows").
		Assess("flows are decorated with zone", testFlowsDecoratedWithZone).
		Assess("interzone bytes are reported as their own metric", testInterZoneMetric).
		Feature()
}

func testFlowsDecoratedWithZone(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// checking pod-to-pod node communication (request)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`k8s_src_name="httppinger",k8s_dst_name=~"testserver.*",` +
			`k8s_src_type="Pod",k8s_dst_type="Pod"` +
			`}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		require.GreaterOrEqual(ct, len(results), 2)
		for _, res := range results {
			assert.Equal(ct, "client-zone", res.Metric["src_zone"])
			assert.Equal(ct, "server-zone", res.Metric["dst_zone"])
		}
	}, testTimeout, 100*time.Millisecond)
	// checking pod-to-pod node communication (response)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`k8s_dst_name="httppinger",k8s_src_name=~"testserver.*",` +
			`k8s_src_type="Pod",k8s_dst_type="Pod"` +
			`}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		require.GreaterOrEqual(ct, len(results), 2)
		for _, res := range results {
			assert.Equal(ct, "server-zone", res.Metric["src_zone"])
			assert.Equal(ct, "client-zone", res.Metric["dst_zone"])
		}
	}, testTimeout, 100*time.Millisecond)

	// checking node-to-node communication (e.g between control plane and workers)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`src_zone="server-zone",dst_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		require.GreaterOrEqual(ct, len(results), 2)
	}, testTimeout, 100*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`dst_zone="server-zone",src_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		require.GreaterOrEqual(ct, len(results), 2)
	}, testTimeout, 100*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`src_zone="client-zone",dst_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		require.GreaterOrEqual(ct, len(results), 2)
	}, testTimeout, 100*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`dst_zone="client-zone",src_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		require.GreaterOrEqual(ct, len(results), 2)
	}, testTimeout, 100*time.Millisecond)
	return ctx
}

func testInterZoneMetric(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// inter-zone bytes are reported
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_inter_zone_bytes_total{` +
			`src_zone="client-zone", dst_zone="server-zone"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_inter_zone_bytes_total{` +
			`dst_zone="client-zone", src_zone="server-zone"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		// AND the reported attributes are different from the flow bytes attributes
		require.NotContains(ct, results, "k8s_src_type")
		require.NotContains(ct, results, "iface_direction")
	}, testTimeout, 100*time.Millisecond)

	// BUT same-zone bytes are not reported in this metric
	results, err := pq.Query(`obi_network_inter_zone_bytes_total{` +
		`src_zone="client-zone", dst_zone="client-zone"}`)
	require.NoError(t, err)
	require.Empty(t, results)
	results, err = pq.Query(`obi_network_inter_zone_bytes_total{` +
		`src_zone="server-zone", dst_zone="server-zone"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	return ctx
}
