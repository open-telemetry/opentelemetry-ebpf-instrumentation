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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes/fake"

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
	listener, port := newTestListener(t)

	ic := &InformersCache{
		Config: &kubecache.Config{
			Port:           port,
			MaxConnections: 1,
			SendTimeout:    10 * time.Millisecond,
		},
		listener: listener,
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
	listener, port := newTestListener(t)

	ic := &InformersCache{
		Config: &kubecache.Config{
			Port:           port,
			MaxConnections: 1,
			SendTimeout:    10 * time.Millisecond,
		},
		listener: listener,
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
	streamCtx, streamCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer streamCancel()

	require.Eventually(t, func() bool {
		var err error
		conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return false
		}

		client := informer.NewEventStreamServiceClient(conn)
		stream, err = client.Subscribe(streamCtx, &informer.SubscribeMessage{})
		return err == nil
	}, 3*time.Second, 25*time.Millisecond, "server never accepted a streaming client")
	t.Cleanup(func() {
		_ = conn.Close()
	})

	cancel()
	require.NoError(t, <-done)

	for {
		_, err := stream.Recv()
		if err != nil {
			require.NotEqual(t, codes.DeadlineExceeded, status.Code(err), "stream was not closed when the server stopped")
			break
		}
	}

	lis, err := net.Listen("tcp", address)
	require.NoError(t, err, "port still bound after Run returned")
	_ = lis.Close()
}

func newTestListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	return listener, listener.Addr().(*net.TCPAddr).Port
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

// Fake ServerStreamingServer implementations used by connection tests.

// immediateStream succeeds immediately on every Send.
type immediateStream struct{ grpc.ServerStream }

func (s *immediateStream) Send(*informer.Event) error { return nil }

type recordingStream struct {
	grpc.ServerStream
	events chan *informer.Event
}

func (s *recordingStream) Send(event *informer.Event) error {
	s.events <- event
	return nil
}

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

// TestConnectionOn is a regression test for
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1903.
// It verifies that sending exits promptly under each failure mode.
func TestConnectionOn(t *testing.T) {
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })

	tests := []struct {
		name        string
		server      grpc.ServerStreamingServer[informer.Event]
		sendTimeout time.Duration
		wantErr     bool
	}{
		{
			name:        "send timeout drops connection",
			server:      &blockingStream{gate: gate},
			sendTimeout: 50 * time.Millisecond,
			wantErr:     true,
		},
		{
			name:        "successful send exits cleanly",
			server:      &immediateStream{},
			sendTimeout: 50 * time.Millisecond,
		},
		{
			name:        "send error drops connection",
			server:      &errStream{err: errors.New("send error")},
			sendTimeout: 50 * time.Millisecond,
			wantErr:     true,
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
				ctx:         t.Context(),
				done:        make(chan struct{}),
			}

			result := make(chan error, 1)
			go func() {
				result <- o.On(&informer.Event{})
			}()

			err := testutil.ReadChannel(t, result, 2*time.Second)
			if tt.wantErr {
				require.Error(t, err)
				testutil.ReadChannel(t, o.done, time.Second)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConnectionOnRespectsContextCancellationDuringSend(t *testing.T) {
	sendCalled := make(chan struct{})
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	o := &connection{
		log:         slog.New(slog.DiscardHandler),
		id:          "test-client",
		server:      &signalBlockingStream{sendCalled: sendCalled, gate: gate},
		sendTimeout: 5 * time.Minute, // large enough that context cancellation wins
		metrics:     instrument.FromContext(context.Background()),
		ctx:         ctx,
		done:        make(chan struct{}),
	}

	result := make(chan error, 1)
	go func() {
		result <- o.On(&informer.Event{})
	}()

	testutil.ReadChannel(t, sendCalled, time.Second)
	cancel()

	require.ErrorIs(t, testutil.ReadChannel(t, result, 2*time.Second), context.Canceled)
	testutil.ReadChannel(t, o.done, time.Second)
}

func TestConnectionOnFiltersEventsBeforeFromEpoch(t *testing.T) {
	stream := &recordingStream{events: make(chan *informer.Event, 4)}
	conn := &connection{
		log:         slog.New(slog.DiscardHandler),
		server:      stream,
		fromEpoch:   100,
		sendTimeout: time.Second,
		metrics:     instrument.FromContext(context.Background()),
		ctx:         t.Context(),
		done:        make(chan struct{}),
	}

	require.NoError(t, conn.On(&informer.Event{
		Type:     informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{StatusTimeEpoch: 99},
	}))
	require.Empty(t, stream.events)

	for _, event := range []*informer.Event{
		{
			Type:     informer.EventType_CREATED,
			Resource: &informer.ObjectMeta{StatusTimeEpoch: 100},
		},
		{
			Type:     informer.EventType_UPDATED,
			Resource: &informer.ObjectMeta{StatusTimeEpoch: 99},
		},
		{
			Type:     informer.EventType_DELETED,
			Resource: &informer.ObjectMeta{StatusTimeEpoch: 99},
		},
		{Type: informer.EventType_SYNC_FINISHED},
	} {
		require.NoError(t, conn.On(event))
		require.Same(t, event, testutil.ReadChannel(t, stream.events, time.Second))
	}
}

func TestBlockedConnectionDoesNotBlockOtherObservers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate := make(chan struct{})
	defer close(gate)
	sendCalled := make(chan struct{})
	stream := &recordingStream{events: make(chan *informer.Event, 2)}
	notifier := meta.NewBaseNotifier(slog.New(slog.DiscardHandler))
	defer notifier.Close()

	for id, server := range map[string]grpc.ServerStreamingServer[informer.Event]{
		"blocked": &signalBlockingStream{sendCalled: sendCalled, gate: gate},
		"healthy": stream,
	} {
		notifier.Subscribe(&connection{
			log:         slog.New(slog.DiscardHandler),
			id:          id,
			server:      server,
			sendTimeout: 5 * time.Minute,
			metrics:     instrument.FromContext(ctx),
			ctx:         ctx,
			done:        make(chan struct{}),
		})
	}

	event := &informer.Event{Type: informer.EventType_CREATED}
	notifier.Notify(event)
	testutil.ReadChannel(t, sendCalled, time.Second)
	require.Same(t, event, testutil.ReadChannel(t, stream.events, time.Second))

	notifier.Notify(event)
	require.Same(t, event, testutil.ReadChannel(t, stream.events, time.Second))
	cancel()
}
