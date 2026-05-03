// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes/fake"

	"go.opentelemetry.io/obi/pkg/internal/helpers/sync"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube/kubecache"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/instrument"
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

func TestEffectiveSendTimeout(t *testing.T) {
	tests := []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{
			name:       "zero uses default",
			configured: 0,
			want:       kubecache.DefaultConfig.SendTimeout,
		},
		{
			name:       "non-zero is unchanged",
			configured: 42 * time.Millisecond,
			want:       42 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, effectiveSendTimeout(tt.configured))
		})
	}
}

// Fake ServerStreamingServer implementations used by handleMessagesQueue tests.

// immediateStream succeeds immediately on every Send.
type immediateStream struct{ grpc.ServerStream }

func (s *immediateStream) Send(*informer.Event) error { return nil }

// errStream returns a fixed error on every Send.
type errStream struct {
	grpc.ServerStream
	err error
}

func (e *errStream) Send(*informer.Event) error { return e.err }

// blockingStream blocks Send until the gate channel is closed.
type blockingStream struct {
	grpc.ServerStream
	gate <-chan struct{}
}

func (b *blockingStream) Send(*informer.Event) error {
	<-b.gate
	return nil
}

// signalBlockingStream closes sendCalled when Send is entered, then blocks on gate.
type signalBlockingStream struct {
	grpc.ServerStream
	sendCalled chan<- struct{}
	gate       <-chan struct{}
}

func (s *signalBlockingStream) Send(*informer.Event) error {
	close(s.sendCalled)
	<-s.gate
	return nil
}

// TestHandleMessagesQueue is a regression test for
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1903.
// It verifies that handleMessagesQueue exits promptly under each failure mode.
func TestHandleMessagesQueue(t *testing.T) {
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })

	tests := []struct {
		name        string
		server      grpc.ServerStreamingServer[informer.Event]
		enqueue     []*informer.Event
		sendTimeout time.Duration
	}{
		{
			name:        "send timeout drops connection",
			server:      &blockingStream{gate: gate},
			enqueue:     []*informer.Event{{}},
			sendTimeout: 50 * time.Millisecond,
		},
		{
			name:        "successful send exits cleanly",
			server:      &immediateStream{},
			enqueue:     []*informer.Event{{}, nil}, // nil stops the loop (see handleMessagesQueue)
			sendTimeout: 50 * time.Millisecond,
		},
		{
			name:        "send error drops connection",
			server:      &errStream{err: errors.New("send error")},
			enqueue:     []*informer.Event{{}},
			sendTimeout: 50 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &connection{
				log:         slog.New(slog.DiscardHandler),
				id:          "test-client",
				server:      tt.server,
				sendTimeout: tt.sendTimeout,
				metrics:     instrument.FromContext(context.Background()),
				messages:    sync.NewQueue[*informer.Event](),
			}
			for _, e := range tt.enqueue {
				o.messages.Enqueue(e)
			}

			done := make(chan struct{})
			go func() {
				o.handleMessagesQueue(context.Background())
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("handleMessagesQueue did not return within 2s")
			}
		})
	}
}

func TestHandleMessagesQueue_RespectsContextCancellationDuringSend(t *testing.T) {
	sendCalled := make(chan struct{})
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })

	o := &connection{
		log:         slog.New(slog.DiscardHandler),
		id:          "test-client",
		server:      &signalBlockingStream{sendCalled: sendCalled, gate: gate},
		sendTimeout: 5 * time.Minute, // large enough that context cancellation wins
		metrics:     instrument.FromContext(context.Background()),
		messages:    sync.NewQueue[*informer.Event](),
	}
	o.messages.Enqueue(&informer.Event{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		o.handleMessagesQueue(ctx)
		close(done)
	}()

	<-sendCalled // wait until Send is blocking before canceling
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleMessagesQueue did not return within 2s after context cancellation")
	}
}
