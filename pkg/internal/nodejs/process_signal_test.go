// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckProcessLivenessUsesSuppliedSignal(t *testing.T) {
	var got syscall.Signal
	err := checkProcessLiveness(func(signal syscall.Signal) error {
		got = signal
		return nil
	})

	require.NoError(t, err)
	require.Equal(t, syscall.Signal(0), got)
}

func TestEnableNodeInspectorUsesSuppliedSignal(t *testing.T) {
	var got syscall.Signal
	err := enableNodeInspector(func(signal syscall.Signal) error {
		got = signal
		return nil
	})

	require.NoError(t, err)
	require.Equal(t, syscall.SIGUSR1, got)
}

func TestProcessSignalingFailsClosed(t *testing.T) {
	unsupported := errors.New("unsupported")

	require.ErrorContains(t, checkProcessLiveness(nil), "signaling is unavailable")
	require.ErrorContains(t, enableNodeInspector(nil), "signaling is unavailable")
	require.ErrorIs(t, checkProcessLiveness(func(syscall.Signal) error {
		return unsupported
	}), unsupported)
	require.ErrorIs(t, enableNodeInspector(func(syscall.Signal) error {
		return unsupported
	}), unsupported)
}

func TestInjectFileUsesSuppliedSIGUSR1AndFailsClosed(t *testing.T) {
	connectCalls := 0
	injector := &NodeInjector{
		connectInspector: func(string, int) (net.Conn, error) {
			connectCalls++
			return nil, errors.New("inspector closed")
		},
	}
	var signals []syscall.Signal

	err := injector.injectFile(1234, nil, func(signal syscall.Signal) error {
		signals = append(signals, signal)
		if signal == syscall.SIGUSR1 {
			return syscall.ENOSYS
		}
		return nil
	})

	require.ErrorIs(t, err, syscall.ENOSYS)
	require.Equal(t, []syscall.Signal{0, syscall.SIGUSR1}, signals)
	require.Equal(t, 1, connectCalls)
}

func TestInjectFileRejectsNilSignalBeforeInspectorSideEffects(t *testing.T) {
	connectCalls := 0
	injector := &NodeInjector{
		connectInspector: func(string, int) (net.Conn, error) {
			connectCalls++
			return nil, nil
		},
	}

	err := injector.injectFile(1234, nil, nil)

	require.ErrorContains(t, err, "signaling is unavailable")
	require.Zero(t, connectCalls)
}
