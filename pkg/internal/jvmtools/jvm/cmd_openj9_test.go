// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewJ9AttacherStartsWithoutConnection(t *testing.T) {
	attacher := newJ9Attacher(slog.Default())

	require.NoError(t, attacher.detach())
}

func TestWriteCommandPreservesSyscallError(t *testing.T) {
	err := writeCommand(-1, "ATTACH_DETACHED")

	require.ErrorIs(t, err, syscall.EBADF)
}

func TestAcquireLockStopsOnContextCancellation(t *testing.T) {
	tmpPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpPath, ".com_ibm_tools_attach"), 0o755))

	first, err := acquireLock(context.Background(), tmpPath, "", "_attachlock")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, releaseLock(first)) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	second, err := acquireLock(ctx, tmpPath, "", "_attachlock")

	require.Equal(t, -1, second)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
}

func TestAcceptClientStopsOnContextCancellation(t *testing.T) {
	listener, _, err := createAttachSocket()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, syscall.Close(listener)) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	conn, err := acceptClient(ctx, listener, 1)

	require.Nil(t, conn)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
}

func TestAcceptClientHandshakeStopsOnContextCancellation(t *testing.T) {
	listener, port, err := createAttachSocket()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, syscall.Close(listener)) })

	peer, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	conn, err := acceptClient(ctx, listener, 1)

	require.Nil(t, conn)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
}

func TestJ9ReaderCancellationAbortsConnectionOnce(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	counted := newCountingConn(client)
	ctx, cancel := context.WithCancel(context.Background())
	connection := newJ9Connection(ctx, counted)
	openJ9Attacher := newJ9Attacher(slog.Default())
	openJ9Attacher.setConnection(connection)
	attacher := NewJAttacher(slog.Default())
	attacher.Init()
	attacher.j9attacher = openJ9Attacher
	reader := &j9Reader{connection: connection}

	readResult := make(chan error, 1)
	go func() {
		_, err := reader.Read(make([]byte, 1))
		readResult <- err
	}()

	select {
	case <-counted.readStarted:
	case <-time.After(time.Second):
		t.Fatal("reader did not block on the controlled peer")
	}
	cancel()

	select {
	case err := <-readResult:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock the OpenJ9 reader")
	}

	require.NoError(t, reader.Close())
	require.NoError(t, attacher.Cleanup())
	require.NoError(t, reader.Abort())
	require.EqualValues(t, 1, counted.closeCalls.Load())
}

func TestJ9GracefulDetachResponseHonorsContext(t *testing.T) {
	client, peer := net.Pipe()
	counted := newCountingConn(client)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	connection := newJ9Connection(ctx, counted)
	reader := &j9Reader{connection: connection}
	peerDone := make(chan struct{})

	go func() {
		defer close(peerDone)
		defer peer.Close()
		buf := make([]byte, 1)
		for {
			if _, err := peer.Read(buf); err != nil || buf[0] == 0 {
				break
			}
		}
		<-ctx.Done()
	}()

	started := time.Now()
	err := reader.Close()

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
	require.EqualValues(t, 1, counted.closeCalls.Load())
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("controlled OpenJ9 peer did not finish")
	}
}

func TestJ9ConnectionStopsCancellationCallbackBeforeCloseReturns(t *testing.T) {
	client, peer := net.Pipe()
	counted := newCountingConn(client)
	ctx, cancel := context.WithCancel(context.Background())
	connection := newJ9Connection(ctx, counted)
	peerDone := make(chan struct{})

	go func() {
		defer close(peerDone)
		defer peer.Close()
		buf := make([]byte, 1)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
			if buf[0] == 0 {
				_, _ = peer.Write([]byte{0})
				return
			}
		}
	}()

	require.NoError(t, connection.closeGracefully())
	deadlineCalls := counted.deadlineCalls.Load()
	cancel()
	time.Sleep(2 * openJ9PollInterval)

	require.Equal(t, deadlineCalls, counted.deadlineCalls.Load())
	require.EqualValues(t, 1, counted.closeCalls.Load())
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("controlled OpenJ9 peer did not finish")
	}
}

func TestAttachContextDoesNotSignalAfterReturn(t *testing.T) {
	attacher := NewJAttacher(slog.Default())
	attacher.Init()
	var returned atomic.Bool
	var signaledAfterReturn atomic.Bool

	reader, err := attacher.AttachContext(
		context.Background(),
		os.Getpid(),
		[]string{"jcmd", "VM.version"},
		true,
		func(syscall.Signal) error {
			if returned.Load() {
				signaledAfterReturn.Store(true)
			}
			return syscall.ENOSYS
		},
	)
	returned.Store(true)

	require.Nil(t, reader)
	require.ErrorIs(t, err, syscall.ENOSYS)
	time.Sleep(2 * openJ9PollInterval)
	require.False(t, signaledAfterReturn.Load())
}

type countingConn struct {
	net.Conn
	readStarted   chan struct{}
	readOnce      sync.Once
	closeCalls    atomic.Int32
	deadlineCalls atomic.Int32
}

func newCountingConn(conn net.Conn) *countingConn {
	return &countingConn{Conn: conn, readStarted: make(chan struct{})}
}

func (c *countingConn) Read(buf []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(buf)
}

func (c *countingConn) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}

func (c *countingConn) SetDeadline(deadline time.Time) error {
	c.deadlineCalls.Add(1)
	return c.Conn.SetDeadline(deadline)
}
