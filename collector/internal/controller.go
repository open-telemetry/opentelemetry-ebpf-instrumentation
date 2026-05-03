// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal // import "go.opentelemetry.io/obi/collector/internal"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
)

// sharedController manages an OBI instance that can be shared between
// traces and metrics receivers with the same component ID.
type sharedController struct {
	mu      sync.Mutex
	config  *obi.Config
	cancel  context.CancelFunc
	refCnt  int // Number of active receivers using this controller
	runErr  error
	runDone chan struct{}
}

// Controller represents an individual receiver (traces or metrics) that
// shares the underlying OBI instance with other receivers of the same component ID.
type Controller struct {
	id     component.ID
	shared *sharedController
}

var (
	// sharedControllers holds shared controller instances keyed by component ID.
	// This allows multiple OBI receivers (e.g., obi/instance1, obi/instance2) to run
	// independently, while traces and metrics receivers with the same ID share one instance.
	sharedControllers   = make(map[component.ID]*sharedController)
	sharedControllersMu sync.Mutex
)

// NewController creates a new Controller for the given component ID and config.
// Receivers with the same component ID share the same underlying OBI instance.
// Receivers with different component IDs get separate OBI instances.
func NewController(id component.ID, cfg *obi.Config) (*Controller, error) {
	sharedControllersMu.Lock()
	defer sharedControllersMu.Unlock()

	// Create or reuse the shared controller for this component ID
	shared, exists := sharedControllers[id]
	if !exists {
		shared = &sharedController{
			config: cfg,
		}
		sharedControllers[id] = shared
	} else {
		// Update config with any new consumers
		// The traces or metrics consumer might be set by different receivers
		if cfg.Traces.TracesConsumer != nil {
			shared.config.Traces.TracesConsumer = cfg.Traces.TracesConsumer
		}
		if cfg.OTELMetrics.MetricsConsumer != nil {
			shared.config.OTELMetrics.MetricsConsumer = cfg.OTELMetrics.MetricsConsumer
		}
	}

	if err := obi.CheckOSSupport(); err != nil {
		slog.Error("can't start OBI Receiver", "error", err, "id", id)
		return nil, err
	}

	if err := obi.CheckOSCapabilities(cfg); err != nil {
		if cfg.EnforceSysCaps {
			slog.Error("can't start OBI Receiver", "error", err, "id", id)
			return nil, err
		}

		slog.Warn("Required system capabilities not present, OBI Receiver may malfunction", "error", err, "id", id)
	}

	cfg.Log()

	return &Controller{
		id:     id,
		shared: shared,
	}, nil
}

// Start starts the receiver. Only the first call actually starts OBI;
// subsequent calls just increase the reference count.
func (c *Controller) Start(ctx context.Context, _ component.Host) error {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()

	c.shared.refCnt++

	if c.shared.refCnt > 1 {
		// Already running, just increased ref count
		return nil
	}

	// First caller - start OBI
	runCtx, cancel := context.WithCancel(ctx)
	ctxInfo, err := instrumenter.BuildCommonContextInfo(runCtx, c.shared.config)
	if err != nil {
		cancel()
		c.shared.refCnt-- // rollback on failure
		slog.Error("building common context info for OBI", "error", err, "id", c.id)
		return err
	}

	c.shared.cancel = cancel
	c.shared.runDone = make(chan struct{})

	// Run OBI in a goroutine
	go func() {
		defer close(c.shared.runDone)
		c.shared.runErr = instrumenter.RunWithContextInfo(runCtx, c.shared.config, ctxInfo)
	}()

	return nil
}

// Shutdown stops the receiver. Only the last shutdown call actually stops OBI.
func (c *Controller) Shutdown(_ context.Context) error {
	c.shared.mu.Lock()
	if c.shared.refCnt == 0 {
		c.shared.mu.Unlock()
		c.cleanupSharedController()
		return nil
	}

	c.shared.refCnt--

	if c.shared.refCnt > 0 {
		c.shared.mu.Unlock()
		// Other receivers still using the shared controller
		return nil
	}

	// Last receiver shutting down, stop OBI
	cancel := c.shared.cancel
	runDone := c.shared.runDone
	c.shared.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	if runDone == nil {
		c.cleanupSharedController()
		return nil
	}

	// Wait for OBI to finish
	<-runDone

	// Clean up the shared controller for this component ID
	c.cleanupSharedController()

	c.shared.mu.Lock()
	runErr := c.shared.runErr
	c.shared.mu.Unlock()

	return runErr
}

func (c *Controller) cleanupSharedController() {
	sharedControllersMu.Lock()
	delete(sharedControllers, c.id)
	sharedControllersMu.Unlock()
}
