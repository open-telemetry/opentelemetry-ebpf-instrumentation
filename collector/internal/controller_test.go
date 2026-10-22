// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestShutdownAfterStartFailureCleansSharedController(t *testing.T) {
	id := component.MustNewIDWithName("obi", "start-failure")
	cfg := &obi.Config{}
	cfg.Attributes.Kubernetes.ServiceNameTemplate = "{{"

	c := newTestController(t, id, cfg)

	if err := c.Start(context.Background(), componenttest.NewNopHost()); err == nil {
		t.Fatal("expected Start to fail")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- c.Shutdown(context.Background())
	}()

	timer := newShutdownTimer(t)
	defer stopTestTimer(timer)

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("expected Shutdown to return nil after failed start, got %v", err)
		}
	case <-timer.C:
		t.Fatal("Shutdown blocked after Start failure")
	}

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown returned error after failed start: %v", err)
	}

	retriedCfg := &obi.Config{}
	retried := newTestController(t, id, retriedCfg)

	if retried.shared == c.shared {
		t.Fatal("expected failed-start shutdown to remove the shared controller for retries")
	}
	if retried.shared.config != retriedCfg {
		t.Fatal("expected retry to use the replacement config")
	}

	if err := retried.Shutdown(context.Background()); err != nil {
		t.Fatalf("retry Shutdown returned error without Start: %v", err)
	}
}

func TestRunOutlivesStartContext(t *testing.T) {
	runCtxs := make(chan context.Context, 1)
	originalRunOBI := runOBI
	t.Cleanup(func() { runOBI = originalRunOBI })
	runOBI = func(
		ctx context.Context, _ *obi.Config, _ *global.ContextInfo,
		_ *instrumentations.InstrumentationSelection, _ ...instrumenter.Option,
	) error {
		runCtxs <- ctx
		<-ctx.Done()
		return nil
	}

	id := component.MustNewIDWithName("obi", "start-context")
	cfg := &obi.Config{}
	cfg.Attributes.HostID.Override = "test-host-id"
	cfg.Attributes.MetadataRetry = metadata.RetryConfig{Timeout: time.Millisecond}
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledFalse
	c := newTestController(t, id, cfg)

	startCtx, cancelStart := context.WithCancel(context.Background())
	if err := c.Start(startCtx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	cancelStart()

	timer := newShutdownTimer(t)
	defer stopTestTimer(timer)

	var runCtx context.Context
	select {
	case runCtx = <-runCtxs:
	case <-timer.C:
		t.Fatal("OBI run loop was not started")
	}
	if runCtx.Err() != nil {
		t.Fatal("canceling the Start context stopped OBI")
	}

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
	if runCtx.Err() == nil {
		t.Fatal("Shutdown did not stop OBI")
	}
}

func TestStartWithCanceledContextDoesNotRunOBI(t *testing.T) {
	runCalls := make(chan struct{}, 1)
	originalRunOBI := runOBI
	t.Cleanup(func() { runOBI = originalRunOBI })
	runOBI = func(
		_ context.Context, _ *obi.Config, _ *global.ContextInfo,
		_ *instrumentations.InstrumentationSelection, _ ...instrumenter.Option,
	) error {
		runCalls <- struct{}{}
		return nil
	}

	id := component.MustNewIDWithName("obi", "canceled-start")
	cfg := &obi.Config{}
	cfg.Attributes.HostID.Override = "test-host-id"
	cfg.Attributes.MetadataRetry = metadata.RetryConfig{Timeout: time.Millisecond}
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledFalse
	c := newTestController(t, id, cfg)

	startCtx, cancelStart := context.WithCancel(context.Background())
	cancelStart()

	if err := c.Start(startCtx, componenttest.NewNopHost()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Start to return context.Canceled, got %v", err)
	}
	select {
	case <-runCalls:
		t.Fatal("OBI was started with a canceled Start context")
	default:
	}

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown returned error after canceled start: %v", err)
	}
	sharedControllersMu.Lock()
	_, stillRegistered := sharedControllers[id]
	sharedControllersMu.Unlock()
	if stillRegistered {
		t.Fatal("shared controller was not removed after canceled start")
	}
}

func TestShutdownOfUnstartedSiblingKeepsOBIRunning(t *testing.T) {
	runCtxs := make(chan context.Context, 1)
	originalRunOBI := runOBI
	t.Cleanup(func() { runOBI = originalRunOBI })
	runOBI = func(
		ctx context.Context, _ *obi.Config, _ *global.ContextInfo,
		_ *instrumentations.InstrumentationSelection, _ ...instrumenter.Option,
	) error {
		runCtxs <- ctx
		<-ctx.Done()
		return nil
	}

	id := component.MustNewIDWithName("obi", "unstarted-sibling")
	cfg := &obi.Config{}
	cfg.Attributes.HostID.Override = "test-host-id"
	cfg.Attributes.MetadataRetry = metadata.RetryConfig{Timeout: time.Millisecond}
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledFalse
	running := newTestController(t, id, cfg)
	sibling := newTestController(t, id, cfg)
	if sibling.shared != running.shared {
		t.Fatal("expected both receivers to share the controller")
	}

	if err := running.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	timer := newShutdownTimer(t)
	defer stopTestTimer(timer)

	var runCtx context.Context
	select {
	case runCtx = <-runCtxs:
	case <-timer.C:
		t.Fatal("OBI run loop was not started")
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sibling.Start(canceledCtx, componenttest.NewNopHost()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected sibling Start to return context.Canceled, got %v", err)
	}

	if err := sibling.Shutdown(context.Background()); err != nil {
		t.Fatalf("sibling Shutdown returned error: %v", err)
	}
	if runCtx.Err() != nil {
		t.Fatal("shutting down the unstarted sibling stopped OBI")
	}
	sharedControllersMu.Lock()
	registered, stillRegistered := sharedControllers[id]
	sharedControllersMu.Unlock()
	if !stillRegistered || registered != running.shared {
		t.Fatal("shutting down the unstarted sibling removed the running receiver's registration")
	}

	if err := running.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
	if runCtx.Err() == nil {
		t.Fatal("Shutdown did not stop OBI")
	}
	sharedControllersMu.Lock()
	_, stillRegistered = sharedControllers[id]
	sharedControllersMu.Unlock()
	if stillRegistered {
		t.Fatal("shared controller was not removed after the last Shutdown")
	}
}

func TestShutdownRespectsContextDeadline(t *testing.T) {
	id := component.MustNewIDWithName("obi", "ctx-deadline")
	c := newTestController(t, id, &obi.Config{})

	// Simulate a running OBI that never finishes: wire up shared state as if
	// Start() succeeded but the OBI goroutine is permanently blocked.
	neverDone := make(chan struct{})
	_, simulatedCancel := context.WithCancel(context.Background())
	defer simulatedCancel()
	c.shared.mu.Lock()
	c.started = true
	c.shared.refCnt = 1
	c.shared.cancel = simulatedCancel
	c.shared.runDone = neverDone
	c.shared.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled so the select fires immediately

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- c.Shutdown(ctx)
	}()

	timer := newShutdownTimer(t)
	defer stopTestTimer(timer)

	select {
	case err := <-shutdownDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-timer.C:
		t.Fatal("Shutdown blocked on runDone when context was already cancelled")
	}

	// Shared controller must be removed even when Shutdown exits via ctx.Done().
	sharedControllersMu.Lock()
	_, stillRegistered := sharedControllers[id]
	sharedControllersMu.Unlock()
	if stillRegistered {
		t.Fatal("shared controller was not removed after context-deadline Shutdown")
	}
}

func TestShutdownWithoutStartCleansSharedController(t *testing.T) {
	id := component.MustNewIDWithName("obi", "shutdown-without-start")

	c := newTestController(t, id, &obi.Config{})

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown returned error: %v", err)
	}

	retriedCfg := &obi.Config{}
	retried := newTestController(t, id, retriedCfg)

	if retried.shared == c.shared {
		t.Fatal("expected never-started shutdown to remove the shared controller")
	}
	if retried.shared.config != retriedCfg {
		t.Fatal("expected replacement controller to use the new config")
	}

	if err := retried.Shutdown(context.Background()); err != nil {
		t.Fatalf("second controller Shutdown returned error: %v", err)
	}
}

func newTestController(t *testing.T, id component.ID, cfg *obi.Config) *Controller {
	t.Helper()

	c, err := NewController(id, cfg, false)
	if err != nil {
		t.Fatalf("NewController returned error: %v", err)
	}

	t.Cleanup(func() {
		sharedControllersMu.Lock()
		delete(sharedControllers, id)
		sharedControllersMu.Unlock()
	})

	return c
}

func newShutdownTimer(t *testing.T) *time.Timer {
	t.Helper()

	timeout := 5 * time.Second
	if deadline, ok := t.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > time.Second && remaining-time.Second < timeout {
			timeout = remaining - time.Second
		}
	}

	return time.NewTimer(timeout)
}

func stopTestTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}

	select {
	case <-timer.C:
	default:
	}
}
