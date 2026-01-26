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
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name="internal-pinger-net",dst_name="testserver"}`)
		if err != nil { return false }
		if len(results) == 0 { return false }

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "ipv4", metric["network_type"])
		assert.Equal(t, "undefined", metric["network_protocol_name"])
		assert.Equal(t, "my-kube", metric["k8s_cluster_name"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Regexp(t,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "testserver", metric["k8s_dst_name"])
		assert.Equal(t, "Service", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Service", metric["k8s_dst_type"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, svcSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
		// services don't have host IP or name
	}, testTimeout, time.Second, "waiting for network metrics")
	// testing request flows (to testserver as Pod)
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name="internal-pinger-net",dst_name=~"testserver-.*"}`)
		if err != nil { return false }
		if len(results) == 0 { return false }

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_src_name"])
		assert.Equal(t, "Pod", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Regexp(t,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Regexp(t, "^testserver-", metric["k8s_dst_name"])
		assert.Equal(t, "Deployment", metric["k8s_dst_owner_type"])
		assert.Equal(t, "testserver", metric["k8s_dst_owner_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Regexp(t,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
	}, testTimeout, time.Second, "waiting for network metrics")

	// testing response flows (from testserver Pod)
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name=~"testserver-.*",dst_name="internal-pinger-net"}`)
		if err != nil { return false }
		if len(results) == 0 { return false }

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Regexp(t, "^testserver-", metric["k8s_src_name"])
		assert.Equal(t, "Deployment", metric["k8s_src_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_src_type"])
		assert.Regexp(t,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_src_node_name"])
		assertIsIP(t, metric["k8s_src_node_ip"])
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_dst_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Regexp(t,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, podSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "TCP", metric["transport"])
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
	}, testTimeout, time.Second, "waiting for network metrics")

	// testing response flows (from testserver Service)
	require.Eventually(t, func() bool {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name="testserver",dst_name="internal-pinger-net"}`)
		if err != nil { return false }
		if len(results) == 0 { return false }

		// check that the metrics are properly decorated
		require.GreaterOrEqual(t, len(results), 1) // tests could establish more than one connection from different client_ports
		metric := results[0].Metric
		assertIsIP(t, metric["src_address"])
		assertIsIP(t, metric["dst_address"])
		assert.Equal(t, "default", metric["k8s_src_namespace"])
		assert.Equal(t, "testserver", metric["k8s_src_name"])
		assert.Equal(t, "Service", metric["k8s_src_owner_type"])
		assert.Equal(t, "Service", metric["k8s_src_type"])
		// services don't have host IP or name
		assert.Equal(t, "default", metric["k8s_dst_namespace"])
		assert.Equal(t, "internal-pinger-net", metric["k8s_dst_name"])
		assert.Equal(t, "Pod", metric["k8s_dst_owner_type"])
		assert.Equal(t, "Pod", metric["k8s_dst_type"])
		assert.Regexp(t,
			"^test-kind-cluster-.*control-plane",
			metric["k8s_dst_node_name"])
		assertIsIP(t, metric["k8s_dst_node_ip"])
		assert.Contains(t, svcSubnets, metric["src_cidr"], metric)
		assert.Contains(t, podSubnets, metric["dst_cidr"], metric)
		assert.Equal(t, "8080", metric["server_port"])
		assert.NotEqual(t, "8080", metric["client_port"])
	}, testTimeout, time.Second, "waiting for network metrics")

	// check that there aren't captured flows if there is no communication
	results, err := pq.Query(`obi_network_flow_bytes_total{src_name="internal-pinger-net",dst_name="otherinstance"}`)
	if err != nil { return false }
	require.Empty(t, results)

	// check that only TCP traffic is captured, according to the Protocols configuration option
	results, err = pq.Query(`obi_network_flow_bytes_total`)
	if err != nil { return false }
	if len(results) == 0 { return false }
	for _, result := range results {
		assert.Equal(t, "TCP", result.Metric["transport"])
	}

	return ctx
}

func testNetFlowBytesForExternalTraffic(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// test external traffic (this test --> prometheus)
	require.Eventually(t, func() bool {
		// checks that at least one source without src kubernetes label is there
		results, err := pq.Query(`obi_network_flow_bytes_total{k8s_dst_owner_name="prometheus",k8s_src_owner_name=""}`)
		if err != nil { return false }
		if len(results) == 0 { return false }
	}, testTimeout, time.Second, "waiting for network metrics")

	// test external traffic (prometheus --> this test)
	require.Eventually(t, func() bool {
		// checks that at least one source without dst kubernetes label is there
		results, err := pq.Query(`obi_network_flow_bytes_total{k8s_src_owner_name="prometheus",k8s_dst_owner_name=""}`)
		if err != nil { return false }
		if len(results) == 0 { return false }
	}, testTimeout, time.Second, "waiting for network metrics")
	return ctx
}

func assertIsIP(t require.TestingT, str string) {
	if net.ParseIP(str) == nil {
		assert.Failf(t, "error parsing IP address", "expected IP. Got %s", str)
	}
}
