// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package service // import "go.opentelemetry.io/obi/pkg/kube/kubecache/service"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"go.opentelemetry.io/obi/pkg/kube/kubecache"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/instrument"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

// InformersCache configures and starts the gRPC service
type InformersCache struct {
	informer.UnimplementedEventStreamServiceServer

	Config *kubecache.Config

	started   atomic.Bool
	listener  net.Listener
	informers *meta.Informers
	log       *slog.Logger

	metrics instrument.InternalMetrics
}

func (ic *InformersCache) Run(ctx context.Context, opts ...meta.InformerOption) error {
	if ic.started.Swap(true) {
		return errors.New("server already started")
	}
	ic.metrics = instrument.FromContext(ctx)
	ic.log = slog.With("component", "server.InformersCache")

	lis := ic.listener
	if lis == nil {
		var err error
		lis, err = net.Listen("tcp", fmt.Sprintf(":%d", ic.Config.Port))
		if err != nil {
			return fmt.Errorf("starting TCP connection: %w", err)
		}
		ic.listener = lis
	}

	informers, err := meta.InitInformers(ctx, opts...)
	if err != nil {
		return fmt.Errorf("initializing informers: %w", err)
	}
	ic.informers = informers

	s := grpc.NewServer(
		// TODO: configure other aspects (e.g. secure connections)
		grpc.MaxConcurrentStreams(uint32(ic.Config.MaxConnections)),
	)
	informer.RegisterEventStreamServiceServer(s, ic)

	ic.log.Info("server listening", "port", ic.Config.Port)

	errs := make(chan error, 1)
	go func() {
		if err := s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errs <- fmt.Errorf("failed to serve: %w", err)
		}
		close(errs)
	}()
	select {
	case <-ctx.Done():
		s.Stop()
		return <-errs
	case err := <-errs:
		return err
	}
}

func effectiveSendTimeout(configured time.Duration) time.Duration {
	if configured == 0 {
		return kubecache.DefaultConfig.SendTimeout
	}
	return configured
}

// Subscribe method of the generated protobuf definition
func (ic *InformersCache) Subscribe(msg *informer.SubscribeMessage, server informer.EventStreamService_SubscribeServer) error {
	// extract peer information to identify it
	p, ok := peer.FromContext(server.Context())
	if !ok {
		return errors.New("failed to extract peer information")
	}
	ic.metrics.ClientConnect()
	ctx, cancel := context.WithCancel(server.Context())
	defer cancel()

	o := &connection{
		log:         ic.log.With("clientID", p.Addr.String()),
		id:          p.Addr.String(),
		server:      server,
		sendTimeout: effectiveSendTimeout(ic.Config.SendTimeout),
		metrics:     ic.metrics,
		fromEpoch:   msg.GetFromTimestampEpoch(),
		ctx:         ctx,
		done:        make(chan struct{}),
	}
	ic.log.Info("client subscribed", "id", o.ID(),
		"fromEpoch", o.fromEpoch,
		"fromLast", time.Since(time.Unix(o.fromEpoch, 0)))
	ic.informers.Subscribe(o)
	// Keep the connection open
	select {
	case <-ctx.Done():
	case <-o.done:
	}
	ic.informers.Unsubscribe(o)
	ic.metrics.ClientDisconnect()
	ic.log.Info("client disconnected", "id", o.ID())
	return nil
}

// connection implements the meta.Observer pattern to store the handle to
// each client connection subscription
type connection struct {
	log *slog.Logger

	id     string
	server grpc.ServerStreamingServer[informer.Event]

	sendTimeout time.Duration

	metrics instrument.InternalMetrics
	// fromEpoch filters snapshot entries whose timestamp is lower than its value.
	fromEpoch int64
	ctx       context.Context
	done      chan struct{}
}

func (o *connection) ID() string {
	return o.id
}

func (o *connection) On(event *informer.Event) error {
	// the client asked for events happening after their last successfully received event
	// so ignore older events to save memory and network
	if event.Type == informer.EventType_CREATED && event.Resource != nil && event.Resource.StatusTimeEpoch < o.fromEpoch {
		return nil
	}
	o.metrics.MessageSubmit()
	timer := time.NewTimer(o.sendTimeout)
	defer timer.Stop()
	if err := o.sendWithTimeout(o.ctx, timer, event); err != nil {
		close(o.done)
		return err
	}
	return nil
}

// sendWithTimeout sends event and drops the connection if Send blocks longer
// than o.sendTimeout (enforced per-Send). Returns a non-nil error whenever the
// caller should stop processing events.
func (o *connection) sendWithTimeout(ctx context.Context, timer *time.Timer, event *informer.Event) error {
	sendErr := make(chan error, 1)
	go func() { sendErr <- o.server.Send(event) }()

	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(o.sendTimeout)

	select {
	case err := <-sendErr:
		if err != nil {
			o.log.Warn("Error sending message. Closing client connection", "clientID", o.ID(), "error", err)
			o.metrics.MessageError()
			return err
		}
		o.metrics.MessageSucceed()
		return nil
	case <-timer.C:
		o.log.Warn("Send timed out. Closing client connection", "clientID", o.ID(), "timeout", o.sendTimeout)
		o.metrics.MessageTimeout()
		// sendErr is buffered; the goroutine exits when gRPC closes the stream on Subscribe's return.
		return context.DeadlineExceeded
	case <-ctx.Done():
		o.log.Debug("context done. Closing client connection")
		return ctx.Err()
	}
}
