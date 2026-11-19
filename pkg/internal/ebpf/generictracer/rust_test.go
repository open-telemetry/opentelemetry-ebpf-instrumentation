// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestRustControllerDiscardsReplacedAttachment(t *testing.T) {
	const pid = app.PID(42)
	current := &rustTarget{}
	controller := &rustController{targets: map[app.PID]*rustTarget{pid: current}}

	replaced := &rustTestLink{}
	controller.commit(pid, &rustTarget{}, rustAttachment{links: []io.Closer{replaced}}, nil)

	require.True(t, replaced.closed, "a replaced attachment must close its probes")
	require.Same(t, current, controller.targets[pid])
	require.Empty(t, current.links, "a replaced attachment must not publish to the current target")
}

func TestRustControllerCloseWaitsForAttachment(t *testing.T) {
	const pid = app.PID(42)
	controller := &rustController{targets: map[app.PID]*rustTarget{}}
	controller.attaching.Add(1)

	closed := make(chan struct{})
	go func() {
		_ = controller.Close()
		close(closed)
	}()

	require.Eventually(t, func() bool {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		return controller.closed
	}, time.Second, time.Millisecond)

	select {
	case <-closed:
		t.Fatal("Close returned while an attachment was in progress")
	default:
	}

	// The commit takes the controller lock, so Close must not hold it while waiting.
	late := &rustTestLink{}
	controller.commit(pid, &rustTarget{}, rustAttachment{links: []io.Closer{late}}, nil)
	controller.attaching.Done()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the attachment finished")
	}
	require.True(t, late.closed, "an attachment finishing after Close must close its probes")
}
