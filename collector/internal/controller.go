// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal // import "go.opentelemetry.io/ebpf-profiler/collector/internal"

import (
	"context"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"

	"go.opentelemetry.io/collector/component"
)

type Controller struct {
	onShutdown func() error
	config     *obi.Config
	cancel     context.CancelFunc
}

func NewController(cfg *obi.Config) (*Controller, error) {
	return &Controller{
		config: cfg,
	}, nil
}

// Start starts the receiver.
func (c *Controller) Start(ctx context.Context, _ component.Host) error {
	ctx, c.cancel = context.WithCancel(ctx)
	return instrumenter.Run(ctx, c.config)
}

// Shutdown stops the receiver.
func (c *Controller) Shutdown(_ context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
