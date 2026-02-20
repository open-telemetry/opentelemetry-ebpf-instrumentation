// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
)

// The IMDS mock needs to be accessible through 169.254.169.254, so we configure the
// Docker network to access it at its original IP without requiring to override
// the IMDS client endpoint.
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

func setupAWSMockIMDS(t *testing.T, network *dockertest.Network) {
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
			"--port", "80",
		},
		ExposedPorts: []string{"80/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"80/tcp": {{HostIP: "127.0.0.1", HostPort: "1338"}},
		},
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
	require.NoError(t, err, "could not connect AWS EC2 IMDS Mock container to network")

	if err := waitUntilReadyToServe("http://127.0.0.1:1338/latest/meta-data/hostname"); err != nil {
		t.Fatal("GCP IMDS Mock container not available after timeout")
	}
	t.Log("AWS EC2 Metadata Mock container started", "state", mockIMDS.Container.State.Status)
}

// unlike the AWS EC2 Imds, there is no mock container providing the Azure metadata,
// so we mock our own.
// The contents served by this mock IMDS are extracted from the official Azure docs:
// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux
func setupMockAzureIMDS(t *testing.T, imdsSubnet *dockertest.Network) {
	t.Helper()
	t.Log("Starting Azure IMDS Mock container...")

	mockIMDS, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "nginx",
		Tag:        versionNginx,
		Name:       fmt.Sprintf("mock-imds-nginx-%d", time.Now().UnixNano()),
		Mounts: []string{
			pathRoot + "/internal/test/integration/components/azure-imds/nginx.conf:/etc/nginx/nginx.conf",
			pathRoot + "/internal/test/integration/components/azure-imds/azure-metadata-mock.json:/azure-metadata-mock.json",
		},
		ExposedPorts: []string{"80/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"80/tcp": {{HostIP: "127.0.0.1", HostPort: "1338"}},
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
		},
	})
	require.NoError(t, err, "could not connect Azure IMDS Mock container to network")

	if err := waitUntilReadyToServe("http://127.0.0.1:1338/metadata/instance/compute"); err != nil {
		t.Fatal("Azure IMDS Mock container not available after timeout")
	}

	t.Log("Azure IMDS Mock container started", "state", mockIMDS.Container.State.Status)
}

// unlike the AWS EC2 IMDS, there is no mock container providing the GCP metadata
// so we mock our own using nginx. Each metadata endpoint is served as plain text,
// matching what the real GCP Compute Engine metadata service returns.
// The GCP metadata client validates the "Metadata-Flavor: Google" response header
// on every request, so nginx is configured to add it on all responses.
func setupMockGCPIMDS(t *testing.T, network *dockertest.Network) {
	t.Helper()
	t.Log("Starting GCP IMDS Mock container...")

	mockIMDS, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "nginx",
		Tag:        versionNginx,
		Name:       fmt.Sprintf("mock-imds-gcp-nginx-%d", time.Now().UnixNano()),
		Mounts: []string{
			pathRoot + "/internal/test/integration/components/gcp-imds/nginx.conf:/etc/nginx/nginx.conf",
		},
		ExposedPorts: []string{"80/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"80/tcp": {{HostIP: "127.0.0.1", HostPort: "1338"}},
		},
	})
	require.NoError(t, err, "could not start GCP IMDS Mock container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(mockIMDS), "could not remove GCP IMDS Mock container")
	})

	// Connect to network at 169.254.169.254 and register the DNS alias used by the
	// GCP metadata client. Docker's embedded DNS will resolve metadata.google.internal
	// to 169.254.169.254, satisfying both the DNS and HTTP probes in metadata.OnGCE().
	err = dockerPool.Client.ConnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
		Container: mockIMDS.Container.ID,
		EndpointConfig: &docker.EndpointConfig{
			Aliases: []string{"mock-imds"},
		},
	})
	require.NoError(t, err, "could not connect GCP IMDS Mock container to network")

	if err := waitUntilReadyToServe("http://127.0.0.1:1338/computeMetadata/v1/project/project-id"); err != nil {
		t.Fatal("GCP IMDS Mock container not available after timeout")
	}
	t.Log("GCP IMDS Mock container started", "state", mockIMDS.Container.State.Status)
}

func waitUntilReadyToServe(metaURL string) error {
	done := make(chan struct{})
	// Wait until the container is ready to serve requests
	go func() {
		for {
			resp, err := http.Get(metaURL)
			if err != nil || resp.StatusCode != http.StatusOK {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			close(done)
			return
		}
	}()
	select {
	case <-done:
		return nil
	case <-time.After(30 * time.Second):
		return errors.New("timeout")
	}
}
