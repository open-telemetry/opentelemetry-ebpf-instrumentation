// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frida

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	discoverexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func TestRemovalKeepsReusedPIDAttached(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	current := &session{start: 42, cancel: cancel}
	manager := &Manager{selected: map[app.PID]uint64{123: 42}, sessions: map[app.PID]*session{123: current}}
	manager.Remove(discoverexec.New(discoverexec.Init{Pid: 123, StartTime: 41}))
	require.NoError(t, ctx.Err(), "a stale exit event cancelled the replacement session")
	target := discoverexec.New(discoverexec.Init{Pid: 123, StartTime: 42})
	manager.Remove(target)
	manager.Remove(target)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
}
