// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal // import "go.opentelemetry.io/ebpf-profiler/collector/internal"

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
)

// sharedController manages a singleton OBI instance that can be shared between
// traces and metrics receivers.
type sharedController struct {
	mu      sync.Mutex
	config  *obi.Config
	cancel  context.CancelFunc
	started bool
	refCnt  int // Number of active receivers using this controller
	runErr  error
	runDone chan struct{}
}

// Controller represents an individual receiver (traces or metrics) that
// shares the underlying OBI instance with other receivers.
type Controller struct {
	shared *sharedController
}

var (
	// globalShared holds the shared controller instance
	globalShared   *sharedController
	globalSharedMu sync.Mutex
)

// NewController creates a new Controller for the given config.
// Multiple receivers with the same config will share the same underlying OBI instance.
func NewController(cfg *obi.Config) (*Controller, error) {
	globalSharedMu.Lock()
	defer globalSharedMu.Unlock()

	// Create or reuse the shared controller
	if globalShared == nil {
		globalShared = &sharedController{
			config:  cfg,
			runDone: make(chan struct{}),
		}
	} else {
		// Update config with any new consumers
		// The traces or metrics consumer might be set by different receivers
		if cfg.Traces.TracesConsumer != nil {
			globalShared.config.Traces.TracesConsumer = cfg.Traces.TracesConsumer
		}
		if cfg.OTELMetrics.MetricsConsumer != nil {
			globalShared.config.OTELMetrics.MetricsConsumer = cfg.OTELMetrics.MetricsConsumer
		}
	}

	return &Controller{
		shared: globalShared,
	}, nil
}

// Start starts the receiver. Only the first call actually starts OBI;
// subsequent calls just increase the reference count.
func (c *Controller) Start(ctx context.Context, _ component.Host) error {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()

	c.shared.refCnt++

	if c.shared.started {
		// Already running, just increase ref count
		return nil
	}

	c.shared.started = true
	ctx, c.shared.cancel = context.WithCancel(ctx)

	// Run OBI in a goroutine
	go func() {
		defer close(c.shared.runDone)
		c.shared.runErr = instrumenter.Run(ctx, c.shared.config)
	}()

	return nil
}

// Shutdown stops the receiver. Only the last shutdown call actually stops OBI.
func (c *Controller) Shutdown(_ context.Context) error {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()

	c.shared.refCnt--

	if c.shared.refCnt > 0 {
		// Other receivers still using the shared controller
		return nil
	}

	// Last receiver shutting down, stop OBI
	if c.shared.cancel != nil {
		c.shared.cancel()
	}

	// Wait for OBI to finish
	<-c.shared.runDone

	// Clean up the global shared controller
	globalSharedMu.Lock()
	globalShared = nil
	globalSharedMu.Unlock()

	return c.shared.runErr
}
