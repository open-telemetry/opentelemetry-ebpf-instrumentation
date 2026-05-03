// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/require"
)

// The IMDS mock needs to be accessible through 169.254.169.254, so we configure the
// Docker network to access it at its original IP without requiring to override
// the IMDS client endpoint.
func setupIMDSSubnet(t *testing.T) dockertest.Network {
	t.Helper()
	t.Log("Starting IMDS Mock network...")

	prefix, err := netip.ParsePrefix("169.254.0.0/16")
	require.NoError(t, err, "could not parse Docker subnet")

	create, err := dockerPool.Client().NetworkCreate(t.Context(), fmt.Sprintf("test-imds-network-%d", time.Now().UnixNano()), client.NetworkCreateOptions{
		IPAM: &network.IPAM{
			Config: []network.IPAMConfig{
				{Subnet: prefix},
			},
		},
	})
	require.NoError(t, err, "could not create Docker IMDS subnet")

	networkID := create.ID
	t.Cleanup(func() {
		_, err := dockerPool.Client().NetworkRemove(context.Background(), networkID, client.NetworkRemoveOptions{})
		require.NoError(t, err, "could not remove Docker IMDS subnet")
	})

	inspect, err := dockerPool.Client().NetworkInspect(t.Context(), networkID, client.NetworkInspectOptions{})
	require.NoError(t, err, "could not inspect Docker IMDS subnet")

	return createdNetwork{inspect: inspect.Network}
}

// createdNetwork adapts a raw Moby network to dockertest.Network.
type createdNetwork struct {
	inspect network.Inspect
}

func (n createdNetwork) ID() string {
	return n.inspect.ID
}

func (n createdNetwork) Inspect() network.Inspect {
	return n.inspect
}

func setupAWSMockIMDS(t *testing.T, net dockertest.Network) {
	t.Helper()

	t.Log("Starting AWS EC2 Metadata Mock container...")
	mockIMDS, err := dockerPool.Run(t.Context(), "amazon/amazon-ec2-metadata-mock",
		dockertest.WithTag(versionAWSMetaMock),
		dockertest.WithName(fmt.Sprintf("mock-imds-test-%d", time.Now().UnixNano())),
		dockertest.WithMounts([]string{
			pathRoot + "/internal/test/integration/configs/aws-metadata-mock.json:/config/aws-metadata-mock.json",
		}),
		dockertest.WithCmd([]string{
			"--config-file", "/config/aws-metadata-mock.json",
			"--port", "80",
		}),
		dockertest.WithPortBindings(portBindings("80/tcp", "1338")),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.ExposedPorts = exposedPorts("80/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start AWS EC2 Metadata Mock container")
	t.Cleanup(func() {
		require.NoError(t, mockIMDS.Close(context.Background()), "could not remove AWS EC2 Metadata Mock container")
	})

	_, err = dockerPool.Client().NetworkConnect(t.Context(), net.ID(), client.NetworkConnectOptions{
		Container:      mockIMDS.ID(),
		EndpointConfig: endpointAliases("mock-imds"),
	})
	require.NoError(t, err, "could not connect AWS EC2 IMDS Mock container to network")

	if err := waitUntilReadyToServe("http://127.0.0.1:1338/latest/meta-data/hostname"); err != nil {
		t.Fatal("GCP IMDS Mock container not available after timeout")
	}
	t.Log("AWS EC2 Metadata Mock container started", "state", mockIMDS.Container().State.Status)
}

// unlike the AWS EC2 Imds, there is no mock container providing the Azure metadata,
// so we mock our own.
// The contents served by this mock IMDS are extracted from the official Azure docs:
// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux
func setupMockAzureIMDS(t *testing.T, imdsSubnet dockertest.Network) {
	t.Helper()
	t.Log("Starting Azure IMDS Mock container...")

	mockIMDS, err := dockerPool.Run(t.Context(), "nginx",
		dockertest.WithTag(versionNginx),
		dockertest.WithName(fmt.Sprintf("mock-imds-nginx-%d", time.Now().UnixNano())),
		dockertest.WithMounts([]string{
			pathRoot + "/internal/test/integration/components/azure-imds/nginx.conf:/etc/nginx/nginx.conf",
			pathRoot + "/internal/test/integration/components/azure-imds/azure-metadata-mock.json:/azure-metadata-mock.json",
		}),
		dockertest.WithPortBindings(portBindings("80/tcp", "1338")),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.ExposedPorts = exposedPorts("80/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start Azure IMDS Mock container")
	t.Cleanup(func() {
		require.NoError(t, mockIMDS.Close(context.Background()), "could not remove Azure IMDS Mock container")
	})

	_, err = dockerPool.Client().NetworkConnect(t.Context(), imdsSubnet.ID(), client.NetworkConnectOptions{
		Container:      mockIMDS.ID(),
		EndpointConfig: endpointIPv4("169.254.169.254"),
	})
	require.NoError(t, err, "could not connect Azure IMDS Mock container to network")

	if err := waitUntilReadyToServe("http://127.0.0.1:1338/metadata/instance/compute"); err != nil {
		t.Fatal("Azure IMDS Mock container not available after timeout")
	}

	t.Log("Azure IMDS Mock container started", "state", mockIMDS.Container().State.Status)
}

// unlike the AWS EC2 IMDS, there is no mock container providing the GCP metadata
// so we mock our own using nginx. Each metadata endpoint is served as plain text,
// matching what the real GCP Compute Engine metadata service returns.
// The GCP metadata client validates the "Metadata-Flavor: Google" response header
// on every request, so nginx is configured to add it on all responses.
func setupMockGCPIMDS(t *testing.T, net dockertest.Network) {
	t.Helper()
	t.Log("Starting GCP IMDS Mock container...")

	mockIMDS, err := dockerPool.Run(t.Context(), "nginx",
		dockertest.WithTag(versionNginx),
		dockertest.WithName(fmt.Sprintf("mock-imds-gcp-nginx-%d", time.Now().UnixNano())),
		dockertest.WithMounts([]string{
			pathRoot + "/internal/test/integration/components/gcp-imds/nginx.conf:/etc/nginx/nginx.conf",
		}),
		dockertest.WithPortBindings(portBindings("80/tcp", "1338")),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.ExposedPorts = exposedPorts("80/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start GCP IMDS Mock container")
	t.Cleanup(func() {
		require.NoError(t, mockIMDS.Close(context.Background()), "could not remove GCP IMDS Mock container")
	})

	// Connect to network at 169.254.169.254 and register the DNS alias used by the
	// GCP metadata client. Docker's embedded DNS will resolve metadata.google.internal
	// to 169.254.169.254, satisfying both the DNS and HTTP probes in metadata.OnGCE().
	_, err = dockerPool.Client().NetworkConnect(t.Context(), net.ID(), client.NetworkConnectOptions{
		Container:      mockIMDS.ID(),
		EndpointConfig: endpointAliases("mock-imds"),
	})
	require.NoError(t, err, "could not connect GCP IMDS Mock container to network")

	if err := waitUntilReadyToServe("http://127.0.0.1:1338/computeMetadata/v1/project/project-id"); err != nil {
		t.Fatal("GCP IMDS Mock container not available after timeout")
	}
	t.Log("GCP IMDS Mock container started", "state", mockIMDS.Container().State.Status)
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
