// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"

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

func TestInjectionTargetFromUsesInspectionIdentity(t *testing.T) {
	stubOpenProcessHandle(t, func(pid app.PID, startTime uint64) (*procs.ProcessHandle, error) {
		require.Equal(t, app.PID(1000), pid)
		require.Equal(t, uint64(4242), startTime)
		return nil, nil
	})

	target, err := InjectionTargetFrom(&ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{
			Pid:       1000,
			StartTime: 4242,
			Service: svc.Attrs{EnvVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			}},
		}),
		Type: svc.InstrumentableJava,
	})

	require.NoError(t, err)
	assert.Equal(t, app.PID(1000), target.Pid)
	assert.Equal(t, uint64(4242), target.StartTime)
	assert.Equal(t, "/custom/tmp", target.TempDirEnv)
}

func TestInjectionTargetFromFailsWhenStableIdentityCannotBeOpened(t *testing.T) {
	stubOpenProcessHandle(t, func(app.PID, uint64) (*procs.ProcessHandle, error) {
		return nil, errors.New("pidfd_send_signal is unavailable")
	})

	target, err := InjectionTargetFrom(&ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{Pid: 1000, StartTime: 4242}),
		Type:     svc.InstrumentableJava,
	})

	require.Error(t, err)
	assert.Zero(t, target)
	assert.Contains(t, err.Error(), "capturing stable identity")
}

func TestVerifyTargetIdentity(t *testing.T) {
	pid := app.PID(syscall.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)

	target := InjectionTarget{
		Type:      svc.InstrumentableJava,
		Pid:       pid,
		StartTime: startTime,
		Process:   process,
	}
	require.NoError(t, verifyTargetIdentity(target))

	require.NoError(t, target.Close())
	err = verifyTargetIdentity(target)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot confirm identity")
}

// A target constructed after its inspected PID was recycled must be rejected
// before it reaches the queue or any attach-side operation.
func TestInjectionTargetFromRejectsReusedPID(t *testing.T) {
	victim := exec.Command("sleep", "60")
	require.NoError(t, victim.Start())
	t.Cleanup(func() {
		_ = victim.Process.Kill()
		_ = victim.Wait()
	})

	pid := app.PID(victim.Process.Pid)
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)

	target, err := InjectionTargetFrom(&ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{
			Pid:       pid,
			StartTime: startTime + 1,
		}),
		Type: svc.InstrumentableJava,
	})

	require.Error(t, err)
	assert.Zero(t, target)
	assert.Contains(t, err.Error(), "was replaced before injection")

	time.Sleep(100 * time.Millisecond)
	assert.NoError(t, victim.Process.Signal(syscall.Signal(0)), "the process holding the reused PID was disturbed")
}

func TestInjectionTargetFromRefusesUnidentifiedProcess(t *testing.T) {
	victim := exec.Command("sleep", "60")
	require.NoError(t, victim.Start())
	t.Cleanup(func() {
		_ = victim.Process.Kill()
		_ = victim.Wait()
	})

	pid := app.PID(victim.Process.Pid)
	target, err := InjectionTargetFrom(&ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{Pid: pid}),
		Type:     svc.InstrumentableJava,
	})

	require.Error(t, err)
	assert.Zero(t, target)
	assert.Contains(t, err.Error(), "identity of process")

	time.Sleep(100 * time.Millisecond)
	assert.NoError(t, victim.Process.Signal(syscall.Signal(0)), "an unidentifiable target was disturbed")
}
