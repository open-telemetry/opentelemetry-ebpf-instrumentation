// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"

	"go.opentelemetry.io/obi/pkg/obi"
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

	c, err := NewController(id, cfg)
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
