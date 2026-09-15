// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execdiscover "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func stubOpenProcessHandle(
	t *testing.T,
	fn func(app.PID, uint64) (*procs.ProcessHandle, error),
) {
	original := openProcessHandle
	t.Cleanup(func() { openProcessHandle = original })
	openProcessHandle = fn
}

func nodeInstrumentable(pid app.PID, startTime uint64) *ebpf.Instrumentable {
	return &ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{Pid: pid, StartTime: startTime}),
		Type:     svc.InstrumentableNodejs,
	}
}

func TestInjectionTargetFromUsesInspectionIdentity(t *testing.T) {
	stubOpenProcessHandle(t, func(pid app.PID, startTime uint64) (*procs.ProcessHandle, error) {
		require.Equal(t, app.PID(1000), pid)
		require.Equal(t, uint64(4242), startTime)
		return nil, nil
	})

	target, err := InjectionTargetFrom(nodeInstrumentable(1000, 4242))

	require.NoError(t, err)
	assert.Equal(t, app.PID(1000), target.Pid)
	assert.Equal(t, app.PID(1000), target.PID())
}

// A target is only worth a queue slot if the incarnation discovery saw can be
// pinned. Without that, the injection would read /proc for, and signal,
// whatever process holds the number by the time it runs.
func TestInjectionTargetFromRefusesUnpinnableProcess(t *testing.T) {
	want := errors.New("identity of process 1000 was not captured")
	stubOpenProcessHandle(t, func(app.PID, uint64) (*procs.ProcessHandle, error) {
		return nil, want
	})

	_, err := InjectionTargetFrom(nodeInstrumentable(1000, 0))

	require.Error(t, err)
	require.ErrorIs(t, err, want)
	assert.Contains(t, err.Error(), "1000")
}

// The queue closes every target it does not inject, including one whose handle
// was never opened.
func TestInjectionTargetCloseWithoutProcess(t *testing.T) {
	assert.NoError(t, InjectionTarget{Pid: 7}.Close())
}
