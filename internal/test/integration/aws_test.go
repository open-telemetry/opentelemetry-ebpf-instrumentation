// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func setupMockIMDS(t *testing.T, network *dockertest.Network) {
	t.Helper()

	t.Log("Starting AWS EC2 Metadata Mock container...")
	mockIMDS, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "amazon/amazon-ec2-metadata-mock",
		Tag:        versionAWSMetaMock,
		Name:       fmt.Sprintf("mock-imds-test-%d", time.Now().UnixNano()),
		Mounts: []string{
			pathRoot + "/internal/test/integration/configs/aws-metadata-mock.json:/config/aws-metadata-mock.json",
		},
		Cmd: []string{
			"--config-file", "/config/aws-metadata-mock.json",
			"--port", "1338",
		},
		ExposedPorts: []string{"1338/tcp"},
	})
	require.NoError(t, err, "could not start AWS EC2 Metadata Mock container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(mockIMDS), "could not remove AWS EC2 Metadata Mock container")
	})

	// Connect to network with alias for metadata service
	err = dockerPool.Client.ConnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
		Container: mockIMDS.Container.ID,
		EndpointConfig: &docker.EndpointConfig{
			Aliases: []string{"mock-imds"},
		},
	})
	require.NoError(t, err, "could not connect AWS EC2 Metadata Mock container to network")
	t.Log("AWS EC2 Metadata Mock container started")
}

// This file contains tests related with the integration with Amazon Web Services
func TestClusterName(t *testing.T) {
	clusterName := "test-eks-cluster"

	network := setupDockerNetwork(t)
	setupContainerPrometheus(t, network, "prometheus-config.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	setupMockIMDS(t, network)
	defer network.Close()
	testserver := setupGoOTelTestServer(t, network, nil)

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	// Configure OBI to use the mock IMDS by setting the EC2 metadata endpoint
	o := obi{
		Env: []string{
			"OTEL_EBPF_OPEN_PORT=8080",
			// Configure AWS SDK to use custom endpoint for EC2 metadata
			// The official amazon-ec2-metadata-mock runs on port 1338
			"AWS_EC2_METADATA_SERVICE_ENDPOINT=http://mock-imds:1338",
		},
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, testserver, "obi-config-aws.yml")

	t.Run("Cluster name from EC2 metadata", func(t *testing.T) {
		// Wait for test components to be ready
		waitForTestComponents(t, "http://localhost:8080")

		// Make some requests to generate metrics
		for range 4 {
			ti.DoHTTPGet(t, "http://localhost:8080/rolldice", 200)
		}

		// Query Prometheus for target_info with cluster_name attribute
		pq := promtest.Client{HostPort: prometheusHostPort}

		// Check that the cluster_name appears in the target_info metric
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			query := fmt.Sprintf(`target_info{k8s_cluster_name="%s"}`, clusterName)
			results, err := pq.Query(query)
			require.NoError(ct, err, "failed to query Prometheus")
			assert.NotEmpty(ct, results, "target_info with k8s_cluster_name should exist")
		}, testTimeout, 500*time.Millisecond)
	})
}
