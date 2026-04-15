// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes/fake"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube/kubecache"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

// TestRunStopsServerOnContextCancellation is a regression test for
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1828.
// It verifies that Run stops the gRPC server and releases the TCP listener
// before returning when the context is canceled.
func TestRunStopsServerOnContextCancellation(t *testing.T) {
	port := testutil.FreeTCPPort(t)

	ic := &InformersCache{
		Config: &kubecache.Config{
			Port:           port,
			MaxConnections: 1,
			SendTimeout:    10 * time.Millisecond,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- ic.Run(
			ctx,
			meta.WithKubeClient(fake.NewSimpleClientset()),
			meta.WithoutNodes(),
			meta.WithoutServices(),
			meta.WaitForCacheSync(),
			meta.WithCacheSyncTimeout(100*time.Millisecond),
		)
	}()

	// Wait until the server is accepting connections.
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout(
			"tcp",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			50*time.Millisecond,
		)
		if err == nil {
			_ = conn.Close()
			return true
		}
		return false
	}, 3*time.Second, 25*time.Millisecond, "server never became ready")

	cancel()
	require.NoError(t, <-done)

	// The port must be free immediately after Run returns.
	lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err, "port still bound after Run returned")
	_ = lis.Close()
}

func TestRunStopsServerOnContextCancellationWithActiveStream(t *testing.T) {
	port := testutil.FreeTCPPort(t)

	ic := &InformersCache{
		Config: &kubecache.Config{
			Port:           port,
			MaxConnections: 1,
			SendTimeout:    10 * time.Millisecond,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- ic.Run(
			ctx,
			meta.WithKubeClient(fake.NewSimpleClientset()),
			meta.WithoutNodes(),
			meta.WithoutServices(),
			meta.WaitForCacheSync(),
			meta.WithCacheSyncTimeout(100*time.Millisecond),
		)
	}()

	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var conn *grpc.ClientConn
	var stream grpc.ServerStreamingClient[informer.Event]

	require.Eventually(t, func() bool {
		var err error
		conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return false
		}

		client := informer.NewEventStreamServiceClient(conn)
		stream, err = client.Subscribe(context.Background(), &informer.SubscribeMessage{})
		return err == nil
	}, 3*time.Second, 25*time.Millisecond, "server never accepted a streaming client")
	t.Cleanup(func() {
		_ = conn.Close()
	})

	cancel()
	require.NoError(t, <-done)

	_, err := stream.Recv()
	require.Error(t, err, "stream should be closed when the server stops")

	lis, err := net.Listen("tcp", address)
	require.NoError(t, err, "port still bound after Run returned")
	_ = lis.Close()
}
