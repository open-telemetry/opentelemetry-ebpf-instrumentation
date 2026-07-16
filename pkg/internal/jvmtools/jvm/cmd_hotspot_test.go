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
	"os/signal"
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

	out, err := attacher.AttachContext(ctx, os.Getpid(), []string{"jcmd"}, true)
	require.Nil(t, out)
	require.ErrorIs(t, err, context.Canceled)
}

func TestStartAttachMechanismStopsOnContextCancellationAndRemovesAttachFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpPath := t.TempDir()
	signal.Ignore(syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGQUIT)

	pid := os.Getpid()
	nspid := 9_999_992
	attachPid := 9_999_993
	attachFile := filepath.Join(tmpPath, fmt.Sprintf(".attach_pid%d", nspid))

	errCh := make(chan error, 1)
	go func() {
		errCh <- startAttachMechanism(ctx, pid, nspid, attachPid, tmpPath)
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
