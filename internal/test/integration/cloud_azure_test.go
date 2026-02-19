// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func setupIMDSSubnet(t *testing.T) *dockertest.Network {
	t.Helper()
	t.Log("Starting IMDS Mock network...")
	imdsSubnet, err := dockerPool.CreateNetwork(fmt.Sprintf("test-imds-network-%d", time.Now().UnixNano()),
		func(opts *docker.CreateNetworkOptions) {
			opts.IPAM = &docker.IPAMOptions{
				Config: []docker.IPAMConfig{
					{
						Subnet: "169.254.0.0/16",
					},
				},
			}
		})
	require.NoError(t, err, "could not create Docker IMDS subnet")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.RemoveNetwork(imdsSubnet), "could not remove Docker IMDS subnet")
	})
	return imdsSubnet
}

func setupMockAzureIMDS(t *testing.T, network, imdsSubnet *dockertest.Network) {
	t.Helper()
	t.Log("Starting Azure IMDS Mock container...")

	// The contents served by this mock IMDS are extracted from the official Azure docs:
	// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux
	mockIMDS, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "nginx",
		Tag:        versionNginx,
		Name:       fmt.Sprintf("mock-imds-nginx-%d", time.Now().UnixNano()),
		Mounts: []string{
			pathRoot + "/internal/test/integration/components/azure-imds/nginx.conf:/etc/nginx/nginx.conf",
			pathRoot + "/internal/test/integration/components/azure-imds/azure-metadata-mock.json:/azure-metadata-mock.json",
		},
	})
	require.NoError(t, err, "could not start Azure IMDS Mock container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(mockIMDS), "could not remove Azure IMDS Mock container")
	})

	// Connect to network with alias for metadata service
	err = dockerPool.Client.ConnectNetwork(imdsSubnet.Network.ID, docker.NetworkConnectionOptions{
		Container: mockIMDS.Container.ID,
		EndpointConfig: &docker.EndpointConfig{
			IPAMConfig: &docker.EndpointIPAMConfig{
				IPv4Address: "169.254.169.254",
			},
			Aliases: []string{"mock-imds"},
		},
	})
	require.NoError(t, err, "could not connect Azure IMDS Mock container to network")
	for mockIMDS.Container.State.Status != "running" {
		t.Log("Waiting for Azure IMDS Mock container to start...", "status", mockIMDS.Container.State.Status)
	}
	t.Log("Azure IMDS Mock container started", "state", mockIMDS.Container.State.Status)
}

// This file contains tests related with the integration with Amazon Web Services
func TestCloudResourceMetadata_Azure(t *testing.T) {
	network := setupDockerNetwork(t)
	imdsSubnet := setupIMDSSubnet(t)

	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	setupMockAzureIMDS(t, network, imdsSubnet)
	defer network.Close()
	testserver := setupGoOTelTestServer(t, network, nil)

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	// Configure OBI to use the mock IMDS by setting the Azure metadata endpoint
	o := obi{
		Env: []string{
			`OTEL_EBPF_PROMETHEUS_PORT=8999`,
			"OTEL_EBPF_OPEN_PORT=8080",
		},
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, testserver, "obi-config.yml", imdsSubnet)

	// Wait for test components to be ready
	waitForTestComponents(t, "http://localhost:8080")

	// Make some requests to generate metrics
	for range 4 {
		ti.DoHTTPGet(t, "http://localhost:8080/rolldice", 200)
	}

	// Query Prometheus for target_info with cluster_name attribute
	pq := promtest.Client{HostPort: prometheusHostPort}

	t.Run("OTEL metrics", func(t *testing.T) {
		testAzureMetrics(t, pq, "rolldice", "otel")
	})
	t.Run("Prometheus metrics", func(t *testing.T) {
		testAzureMetrics(t, pq, "rolldice", "prometheus")
	})
	t.Run("OTEL traces", func(t *testing.T) {
		testAzureTraces(t)
	})
}

func testAzureMetrics(t *testing.T, pq promtest.Client, serviceName, exporter string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// attribute values taken from aws-metadata-mock.json
		query := `target_info{` +
			`service_name="` + serviceName + `",` +
			`exported="` + exporter + `",` +
			`cloud_platform="azure.vm",` +
			`cloud_provider="azure",` +
			`cloud_region="westus",` +
			`cloud_resource_id="/long/tail/of/stuff",` +
			`host_id="02aab8a4-74ef-476e-8182-f6d2ba4166a6",` +
			`host_type="Standard_A3"` +
			`}`
		results, err := pq.Query(query)
		require.NoError(ct, err, "failed to query metrics")
		assert.NotEmpty(ct, results, "target_info with cloud metadata should exist")
	}, testTimeout, 500*time.Millisecond)
}

func testAzureTraces(t *testing.T) {
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2Frolldice")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
		require.Len(ct, trace.Spans, 3) // parent - in queue - processing
	}, testTimeout, 100*time.Millisecond)

	for _, proc := range trace.Processes {
		sd := jaeger.DiffAsRegexp([]jaeger.Tag{
			{Key: "cloud.platform", Type: "string", Value: "^azure.vm$"},
			{Key: "cloud.provider", Type: "string", Value: "^azure$"},
			{Key: "cloud.region", Type: "string", Value: "^westus$"},
			{Key: "cloud.resource_id", Type: "string", Value: "^/long/tail/of/stuff$"},
			{Key: "host.id", Type: "string", Value: "^02aab8a4-74ef-476e-8182-f6d2ba4166a6$"},
			{Key: "host.type", Type: "string", Value: "^Standard_A3$"},
		}, proc.Tags)
		require.Empty(t, sd)
	}
}
