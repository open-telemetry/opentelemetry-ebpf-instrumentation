// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAttachContextReturnsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)))

	out, err := attacher.AttachContext(ctx, os.Getpid(), []string{"jcmd"}, true, nil)
	require.Nil(t, out)
	require.ErrorIs(t, err, context.Canceled)
}

func TestAttachContextFailsClosedWithoutSignalProcess(t *testing.T) {
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)))

	out, err := attacher.AttachContext(
		context.Background(),
		os.Getpid(),
		[]string{"jcmd"},
		true,
		nil,
	)
	require.Nil(t, out)
	require.ErrorContains(t, err, "signaling is unavailable")
}

func TestStartAttachMechanismStopsOnContextCancellationAndRemovesAttachFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpPath := t.TempDir()

	nspid := 9_999_992
	attachPid := 9_999_993
	attachFile := filepath.Join(tmpPath, fmt.Sprintf(".attach_pid%d", nspid))

	errCh := make(chan error, 1)
	go func() {
		errCh <- startAttachMechanism(ctx, nspid, attachPid, tmpPath, func(syscall.Signal) error {
			return nil
		})
	}()

	require.Eventually(t, func() bool {
		_, err := os.Stat(attachFile)
		return err == nil
	}, time.Second, time.Millisecond)

	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for startAttachMechanism to stop")
	}

	_, err := os.Stat(attachFile)
	require.True(t, os.IsNotExist(err), "attach file should be removed, stat error: %v", err)
}

func TestStartAttachMechanismUsesSuppliedSignal(t *testing.T) {
	tmpPath := t.TempDir()
	nspid := 9_999_994
	attachPid := 9_999_995
	attachFile := filepath.Join(tmpPath, fmt.Sprintf(".attach_pid%d", nspid))
	var signals []syscall.Signal

	err := startAttachMechanism(
		context.Background(),
		nspid,
		attachPid,
		tmpPath,
		func(signal syscall.Signal) error {
			signals = append(signals, signal)
			if signal == syscall.SIGQUIT {
				return syscall.ENOSYS
			}
			return nil
		},
	)

	require.ErrorIs(t, err, syscall.ENOSYS)
	require.Equal(t, []syscall.Signal{0, syscall.SIGQUIT}, signals)
	_, statErr := os.Stat(attachFile)
	require.True(t, os.IsNotExist(statErr), "attach file should be removed, stat error: %v", statErr)
}

func TestStartAttachMechanismRejectsNilSignalBeforeSideEffects(t *testing.T) {
	tmpPath := t.TempDir()
	nspid := 9_999_996
	attachPid := 9_999_997
	attachFile := filepath.Join(tmpPath, fmt.Sprintf(".attach_pid%d", nspid))

	err := startAttachMechanism(context.Background(), nspid, attachPid, tmpPath, nil)

	require.ErrorContains(t, err, "signaling is unavailable")
	_, statErr := os.Stat(attachFile)
	require.True(t, os.IsNotExist(statErr), "attach file should not be created, stat error: %v", statErr)
}

func TestWriteHotspotCommandClosesSocketOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := newBlockingConn()
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeHotspotCommand(ctx, conn, []string{"jcmd"})
	}()

	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for socket write to start")
	}

	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for writeHotspotCommand to stop")
	}

	select {
	case <-conn.closed:
	default:
		t.Fatal("expected canceled context to close the socket")
	}
}

func TestWaitForHotspotCancellationCallbackBeforeReturn(t *testing.T) {
	done := make(chan struct{}, 1)
	done <- struct{}{}
	stopCalled := false

	waitForHotspotCancellation(func() bool {
		stopCalled = true
		return false
	}, done)

	require.True(t, stopCalled)
	select {
	case <-done:
		t.Fatal("returned without consuming the callback completion")
	default:
	}
}

type blockingConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingConn() *blockingConn {
	return &blockingConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *blockingConn) Write(_ []byte) (int, error) {
	c.startOnce.Do(func() {
		close(c.writeStarted)
	})
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *blockingConn) LocalAddr() net.Addr {
	return testAddr("local")
}

func (c *blockingConn) RemoteAddr() net.Addr {
	return testAddr("remote")
}

func (c *blockingConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *blockingConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *blockingConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type testAddr string

func (a testAddr) Network() string {
	return string(a)
}

func (a testAddr) String() string {
	return string(a)
}
