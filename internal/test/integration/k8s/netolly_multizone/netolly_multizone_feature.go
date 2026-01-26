// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/internal/test/integration/k8s/netolly_multizone"

import (
	"context"
	"testing"
	"time"

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
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`k8s_src_name="httppinger",k8s_dst_name=~"testserver.*",` +
			`k8s_src_type="Pod",k8s_dst_type="Pod"` +
			`}`)
		if err != nil || len(results) < 2 {
			return false
		}
		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		for _, res := range results {
			if res.Metric["src_zone"] != "client-zone" || res.Metric["dst_zone"] != "server-zone" {
				return false
			}
		}
		return true
	}, testTimeout, 500*time.Millisecond, "pod-to-pod request flows not decorated with zone")
	// checking pod-to-pod node communication (response)
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`k8s_dst_name="httppinger",k8s_src_name=~"testserver.*",` +
			`k8s_src_type="Pod",k8s_dst_type="Pod"` +
			`}`)
		if err != nil || len(results) < 2 {
			return false
		}
		// check that the metrics are properly decorated
		// should have 2 exact metrics, measured from OBI instances in both nodes
		for _, res := range results {
			if res.Metric["src_zone"] != "server-zone" || res.Metric["dst_zone"] != "client-zone" {
				return false
			}
		}
		return true
	}, testTimeout, 500*time.Millisecond, "pod-to-pod response flows not decorated with zone")

	// checking node-to-node communication (e.g between control plane and workers)
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`src_zone="server-zone",dst_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		if err != nil || len(results) < 2 {
			return false
		}
		return true
	}, testTimeout, 500*time.Millisecond, "node-to-node flows server->control not found")
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`dst_zone="server-zone",src_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		if err != nil || len(results) < 2 {
			return false
		}
		return true
	}, testTimeout, 500*time.Millisecond, "node-to-node flows control->server not found")
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`src_zone="client-zone",dst_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		if err != nil || len(results) < 2 {
			return false
		}
		return true
	}, testTimeout, 500*time.Millisecond, "node-to-node flows client->control not found")
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{` +
			`dst_zone="client-zone",src_zone="control-plane-zone",` +
			`k8s_src_type="Node",k8s_dst_type="Node"` +
			`}`)
		if err != nil || len(results) < 2 {
			return false
		}
		return true
	}, testTimeout, 500*time.Millisecond, "node-to-node flows control->client not found")
	return ctx
}

func testInterZoneMetric(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// inter-zone bytes are reported
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_inter_zone_bytes_total{` +
			`src_zone="client-zone", dst_zone="server-zone"}`)
		return err == nil && len(results) > 0
	}, testTimeout, 500*time.Millisecond, "inter-zone bytes client->server not found")
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_inter_zone_bytes_total{` +
			`dst_zone="client-zone", src_zone="server-zone"}`)
		if err != nil || len(results) == 0 {
			return false
		}
		// AND the reported attributes are different from the flow bytes attributes
		for _, res := range results {
			if _, hasType := res.Metric["k8s_src_type"]; hasType {
				return false
			}
			if _, hasDirection := res.Metric["iface_direction"]; hasDirection {
				return false
			}
		}
		return true
	}, testTimeout, 500*time.Millisecond, "inter-zone bytes server->client not found or has wrong attributes")

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
