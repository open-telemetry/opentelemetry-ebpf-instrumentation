// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/internal/test/integration/k8s/netolly"

import (
	"context"
	"net"
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

// values according to official Kind documentation: https://kind.sigs.k8s.io/docs/user/configuration/#pod-subnet
var (
	podSubnets = []string{"10.244.0.0/16", "fd00:10:244::/56"}
	svcSubnets = []string{"10.96.0.0/16", "fd00:10:96::/112"}
)

func FeatureNetworkFlowBytes() features.Feature {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger-net",
			TargetURL: "http://testserver:8080/iping",
		},
	}
	return features.New("network flow bytes").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("catches network metrics between connected pods", testNetFlowBytesForExistingConnections).
		Assess("catches external traffic", testNetFlowBytesForExternalTraffic).
		Feature()
}

func testNetFlowBytesForExistingConnections(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	// testing request flows (to testserver as Service)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name="internal-pinger-net",dst_name="testserver"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(ct, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(ct, metric["src_address"])
		assertIsIP(ct, metric["dst_address"])
		assert.Equal(ct, "ipv4", metric["network_type"])
		assert.Equal(ct, "undefined", metric["network_protocol_name"])
		assert.Equal(ct, "my-kube", metric["k8s_cluster_name"])
		assert.Equal(ct, "default", metric["k8s_src_namespace"])
		assert.Equal(ct, "internal-pinger-net", metric["k8s_src_name"])
		assert.Equal(ct, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(ct, "Pod", metric["k8s_src_type"])
		assert.Regexp(ct,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(ct, metric["k8s_src_node_ip"])
		assert.Equal(ct, "default", metric["k8s_dst_namespace"])
		assert.Equal(ct, "testserver", metric["k8s_dst_name"])
		assert.Equal(ct, "Service", metric["k8s_dst_owner_type"])
		assert.Equal(ct, "Service", metric["k8s_dst_type"])
		assert.Contains(ct, podSubnets, metric["src_cidr"], metric)
		assert.Contains(ct, svcSubnets, metric["dst_cidr"], metric)
		assert.Equal(ct, "8080", metric["server_port"])
		assert.NotEqual(ct, "8080", metric["client_port"])
		// services don't have host IP or name
	}, testTimeout, 100*time.Millisecond)
	// testing request flows (to testserver as Pod)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name="internal-pinger-net",dst_name=~"testserver-.*"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(ct, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(ct, metric["src_address"])
		assertIsIP(ct, metric["dst_address"])
		assert.Equal(ct, "default", metric["k8s_src_namespace"])
		assert.Equal(ct, "internal-pinger-net", metric["k8s_src_name"])
		assert.Equal(ct, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(ct, "Pod", metric["k8s_src_type"])
		assert.Regexp(ct,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(ct, metric["k8s_src_node_ip"])
		assert.Equal(ct, "default", metric["k8s_dst_namespace"])
		assert.Regexp(ct, "^testserver-", metric["k8s_dst_name"])
		assert.Equal(ct, "Deployment", metric["k8s_dst_owner_type"])
		assert.Equal(ct, "testserver", metric["k8s_dst_owner_name"])
		assert.Equal(ct, "Pod", metric["k8s_dst_type"])
		assert.Regexp(ct,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_dst_node_name"])
		assertIsIP(ct, metric["k8s_dst_node_ip"])
		assert.Contains(ct, podSubnets, metric["src_cidr"], metric)
		assert.Contains(ct, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(ct, "8080", metric["server_port"])
		assert.NotEqual(ct, "8080", metric["client_port"])
	}, testTimeout, 100*time.Millisecond)

	// testing response flows (from testserver Pod)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name=~"testserver-.*",dst_name="internal-pinger-net"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(ct, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(ct, metric["src_address"])
		assertIsIP(ct, metric["dst_address"])
		assert.Equal(ct, "default", metric["k8s_src_namespace"])
		assert.Regexp(ct, "^testserver-", metric["k8s_src_name"])
		assert.Equal(ct, "Deployment", metric["k8s_src_owner_type"])
		assert.Equal(ct, "Pod", metric["k8s_src_type"])
		assert.Regexp(ct,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(ct, metric["k8s_src_node_ip"])
		assert.Equal(ct, "default", metric["k8s_dst_namespace"])
		assert.Equal(ct, "internal-pinger-net", metric["k8s_dst_name"])
		assert.Equal(ct, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(ct, "Pod", metric["k8s_dst_type"])
		assert.Regexp(ct,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_dst_node_name"])
		assertIsIP(ct, metric["k8s_dst_node_ip"])
		assert.Contains(ct, podSubnets, metric["src_cidr"], metric)
		assert.Contains(ct, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(ct, "TCP", metric["transport"])
		assert.Equal(ct, "8080", metric["server_port"])
		assert.NotEqual(ct, "8080", metric["client_port"])
	}, testTimeout, 100*time.Millisecond)

	// testing response flows (from testserver Service)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name="testserver",dst_name="internal-pinger-net"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		// check that the metrics are properly decorated
		require.GreaterOrEqual(ct, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(ct, metric["src_address"])
		assertIsIP(ct, metric["dst_address"])
		assert.Equal(ct, "default", metric["k8s_src_namespace"])
		assert.Equal(ct, "testserver", metric["k8s_src_name"])
		assert.Equal(ct, "Service", metric["k8s_src_owner_type"])
		assert.Equal(ct, "Service", metric["k8s_src_type"])
		// services don't have host IP or name
		assert.Equal(ct, "default", metric["k8s_dst_namespace"])
		assert.Equal(ct, "internal-pinger-net", metric["k8s_dst_name"])
		assert.Equal(ct, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(ct, "Pod", metric["k8s_dst_type"])
		assert.Regexp(ct,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_dst_node_name"])
		assertIsIP(ct, metric["k8s_dst_node_ip"])
		assert.Contains(ct, svcSubnets, metric["src_cidr"], metric)
		assert.Contains(ct, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(ct, "8080", metric["server_port"])
		assert.NotEqual(ct, "8080", metric["client_port"])
	}, testTimeout, 100*time.Millisecond)

	// check that there aren't captured flows if there is no communication
	results, err := pq.Query(`obi_network_flow_bytes_total{src_name="internal-pinger-net",dst_name="otherinstance"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	// check that only TCP traffic is captured, according to the Protocols configuration option
	results, err = pq.Query(`obi_network_flow_bytes_total`)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, result := range results {
		assert.Equal(t, "TCP", result.Metric["transport"])
	}

	return ctx
}

func testNetFlowBytesForExternalTraffic(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// test external traffic (this test --> prometheus)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// checks that at least one source without src kubernetes label is there
		results, err := pq.Query(`obi_network_flow_bytes_total{k8s_dst_owner_name="prometheus",k8s_src_owner_name=""}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)

	// test external traffic (prometheus --> this test)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// checks that at least one source without dst kubernetes label is there
		results, err := pq.Query(`obi_network_flow_bytes_total{k8s_src_owner_name="prometheus",k8s_dst_owner_name=""}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)
	return ctx
}

func assertIsIP(t require.TestingT, str string) {
	if net.ParseIP(str) == nil {
		assert.Failf(t, "error parsing IP address", "expected IP. Got %s", str)
	}
}
