// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
	"errors"
	"log/slog"
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
	"go.opentelemetry.io/obi/pkg/obi"
)

func stubProcessStartTime(t *testing.T, fn func(app.PID) (uint64, error)) {
	original := processStartTime
	t.Cleanup(func() { processStartTime = original })
	processStartTime = fn
}

func TestInjectionTargetFrom_CapturesStartTime(t *testing.T) {
	stubProcessStartTime(t, func(pid app.PID) (uint64, error) {
		require.Equal(t, app.PID(1000), pid)
		return 4242, nil
	})

	target := InjectionTargetFrom(&ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{Pid: 1000}),
		Type:     svc.InstrumentableJava,
	})

	assert.Equal(t, uint64(4242), target.StartTime)
}

func TestInjectionTargetFrom_UnreadableStartTime(t *testing.T) {
	stubProcessStartTime(t, func(app.PID) (uint64, error) {
		return 0, errors.New("no such process")
	})

	target := InjectionTargetFrom(&ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{Pid: 1000}),
		Type:     svc.InstrumentableJava,
	})

	assert.Zero(t, target.StartTime)
}

func TestVerifyTargetIdentity(t *testing.T) {
	tests := []struct {
		name          string
		startTime     uint64
		current       func(app.PID) (uint64, error)
		errorContains string
	}{
		{
			name:      "same process",
			startTime: 4242,
			current:   func(app.PID) (uint64, error) { return 4242, nil },
		},
		{
			name:      "start time unknown, target is refused",
			startTime: 0,
			current: func(app.PID) (uint64, error) {
				t.Error("start time must not be read when none was captured")
				return 0, nil
			},
			errorContains: "identity of process 1000 was not captured",
		},
		{
			name:          "pid reused by another process",
			startTime:     4242,
			current:       func(app.PID) (uint64, error) { return 5353, nil },
			errorContains: "was replaced before injection",
		},
		{
			name:          "process is gone",
			startTime:     4242,
			current:       func(app.PID) (uint64, error) { return 0, errors.New("no such process") },
			errorContains: "cannot confirm identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubProcessStartTime(t, tt.current)

			err := verifyTargetIdentity(InjectionTarget{
				Type:      svc.InstrumentableJava,
				Pid:       1000,
				StartTime: tt.startTime,
			})

			if tt.errorContains == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

// A target queued before its PID was recycled must be left alone: the attach
// sequence signals the process with SIGQUIT and writes into its root
// filesystem, which would terminate or corrupt an unrelated program.
func TestJavaInjector_NewExecutableLeavesReusedPIDAlone(t *testing.T) {
	victim := exec.Command("sleep", "60")
	require.NoError(t, victim.Start())
	t.Cleanup(func() {
		_ = victim.Process.Kill()
		_ = victim.Wait()
	})

	pid := app.PID(victim.Process.Pid)

	startTime, err := processStartTime(pid)
	require.NoError(t, err)

	injector := &JavaInjector{
		cfg: &obi.DefaultConfig,
		log: slog.With("component", "javaagent.Injector"),
	}

	// The captured start time belongs to the process that has since exited, so
	// it never matches the one now holding this PID.
	err = injector.NewExecutable(t.Context(), InjectionTarget{
		Type:      svc.InstrumentableJava,
		Pid:       pid,
		StartTime: startTime + 1,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "was replaced before injection")

	// SIGQUIT would have terminated the replacement process.
	time.Sleep(100 * time.Millisecond)
	assert.NoError(t, victim.Process.Signal(syscall.Signal(0)), "the process holding the reused PID was disturbed")
}

// A start time that could not be read at discovery leaves the target with no
// identity to check later, so the whole path from InjectionTargetFrom to the
// attach must fail closed. Injecting anyway would signal whichever process
// holds the PID by the time the queue reaches it.
func TestJavaInjector_NewExecutableRefusesUnidentifiedTarget(t *testing.T) {
	victim := exec.Command("sleep", "60")
	require.NoError(t, victim.Start())
	t.Cleanup(func() {
		_ = victim.Process.Kill()
		_ = victim.Wait()
	})

	pid := app.PID(victim.Process.Pid)

	stubProcessStartTime(t, func(app.PID) (uint64, error) {
		return 0, errors.New("no such process")
	})

	target := InjectionTargetFrom(&ebpf.Instrumentable{
		FileInfo: execdiscover.New(execdiscover.Init{Pid: pid}),
		Type:     svc.InstrumentableJava,
	})
	require.Zero(t, target.StartTime)

	injector := &JavaInjector{
		cfg: &obi.DefaultConfig,
		log: slog.With("component", "javaagent.Injector"),
	}

	err := injector.NewExecutable(t.Context(), target)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "was not captured")

	// SIGQUIT would have terminated the process holding the PID.
	time.Sleep(100 * time.Millisecond)
	assert.NoError(t, victim.Process.Signal(syscall.Signal(0)), "an unidentifiable target was disturbed")
}
