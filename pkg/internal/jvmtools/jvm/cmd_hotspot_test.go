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

func TestAttachReturnsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	const attachID int64 = 1

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), attachID, func() int64 {
		return attachID
	})

	out, err := attacher.Attach(ctx, os.Getpid(), []string{"jcmd"}, true)
	require.Nil(t, out)
	require.ErrorIs(t, err, context.Canceled)
}

func TestCleanupWithoutInitDoesNotSetCredentials(t *testing.T) {
	originalSetEUID := setEUID
	originalSetEGID := setEGID
	t.Cleanup(func() {
		setEUID = originalSetEUID
		setEGID = originalSetEGID
	})

	var euidCalls []int
	var egidCalls []int
	setEUID = func(id int) error {
		euidCalls = append(euidCalls, id)
		return nil
	}
	setEGID = func(id int) error {
		egidCalls = append(egidCalls, id)
		return nil
	}

	const attachID int64 = 1

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), attachID, func() int64 {
		return attachID
	})

	require.NoError(t, attacher.Terminate())
	require.Empty(t, euidCalls)
	require.Empty(t, egidCalls)
}

func TestInitIsIdempotent(t *testing.T) {
	originalGetEUID := getEUID
	originalGetEGID := getEGID
	originalSetEUID := setEUID
	originalSetEGID := setEGID
	t.Cleanup(func() {
		getEUID = originalGetEUID
		getEGID = originalGetEGID
		setEUID = originalSetEUID
		setEGID = originalSetEGID
	})

	euidCalls := 0
	egidCalls := 0
	getEUID = func() int {
		euidCalls++
		return 123
	}
	getEGID = func() int {
		egidCalls++
		return 456
	}
	setEUID = func(int) error {
		return nil
	}
	setEGID = func(int) error {
		return nil
	}

	const attachID int64 = 1

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), attachID, func() int64 {
		return attachID
	})

	attacher.Init()
	require.NoError(t, attacher.Cleanup())
	attacher.Init()

	require.Equal(t, 1, euidCalls)
	require.Equal(t, 1, egidCalls)
	require.Equal(t, 123, attacher.myUID)
	require.Equal(t, 456, attacher.myGID)
	require.True(t, attacher.initialized)
}

func TestCleanupCanRunRepeatedly(t *testing.T) {
	originalGetEUID := getEUID
	originalGetEGID := getEGID
	originalSetEUID := setEUID
	originalSetEGID := setEGID
	t.Cleanup(func() {
		getEUID = originalGetEUID
		getEGID = originalGetEGID
		setEUID = originalSetEUID
		setEGID = originalSetEGID
	})

	var euidCalls []int
	var egidCalls []int
	getEUID = func() int {
		return 123
	}
	getEGID = func() int {
		return 456
	}
	setEUID = func(id int) error {
		euidCalls = append(euidCalls, id)
		return nil
	}
	setEGID = func(id int) error {
		egidCalls = append(egidCalls, id)
		return nil
	}

	const attachID int64 = 1

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), attachID, func() int64 {
		return attachID
	})

	attacher.Init()
	require.NoError(t, attacher.Cleanup())
	require.NoError(t, attacher.Cleanup())
	require.Equal(t, []int{123, 123}, euidCalls)
	require.Equal(t, []int{456, 456}, egidCalls)
	require.True(t, attacher.initialized)
}

func TestDelayedCleanupDoesNotRestoreCredentialsDuringNewAttachAttemptForSamePID(t *testing.T) {
	originalGetEUID := getEUID
	originalGetEGID := getEGID
	originalSetEUID := setEUID
	originalSetEGID := setEGID
	t.Cleanup(func() {
		getEUID = originalGetEUID
		getEGID = originalGetEGID
		setEUID = originalSetEUID
		setEGID = originalSetEGID
	})

	var euidCalls []int
	var egidCalls []int
	getEUID = func() int {
		return 123
	}
	getEGID = func() int {
		return 456
	}
	setEUID = func(id int) error {
		euidCalls = append(euidCalls, id)
		return nil
	}
	setEGID = func(id int) error {
		egidCalls = append(egidCalls, id)
		return nil
	}

	activeAttachID := int64(1)
	getActiveAttachID := func() int64 {
		return activeAttachID
	}

	oldAttacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), activeAttachID, getActiveAttachID)
	oldAttacher.Init()
	require.NoError(t, oldAttacher.Terminate())

	euidCalls = nil
	egidCalls = nil
	activeAttachID = 2

	newAttacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), activeAttachID, getActiveAttachID)
	newAttacher.Init()
	require.NoError(t, newAttacher.setEGID(987))
	require.NoError(t, newAttacher.setEUID(789))

	require.NoError(t, oldAttacher.Cleanup())
	require.Equal(t, []int{789}, euidCalls)
	require.Equal(t, []int{987}, egidCalls)

	require.NoError(t, newAttacher.Cleanup())
	require.Equal(t, []int{789, 123}, euidCalls)
	require.Equal(t, []int{987, 456}, egidCalls)
}

func TestTerminalCleanupPreventsLaterCredentialChanges(t *testing.T) {
	originalGetEUID := getEUID
	originalGetEGID := getEGID
	originalSetEUID := setEUID
	originalSetEGID := setEGID
	t.Cleanup(func() {
		getEUID = originalGetEUID
		getEGID = originalGetEGID
		setEUID = originalSetEUID
		setEGID = originalSetEGID
	})

	var euidCalls []int
	var egidCalls []int
	getEUID = func() int {
		return 123
	}
	getEGID = func() int {
		return 456
	}
	setEUID = func(id int) error {
		euidCalls = append(euidCalls, id)
		return nil
	}
	setEGID = func(id int) error {
		egidCalls = append(egidCalls, id)
		return nil
	}

	const attachID int64 = 1

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), attachID, func() int64 {
		return attachID
	})
	attacher.Init()
	require.NoError(t, attacher.Terminate())

	require.ErrorIs(t, attacher.setEUID(789), errTerminated)
	require.ErrorIs(t, attacher.setEGID(987), errTerminated)
	require.NoError(t, attacher.setEUID(123))
	require.NoError(t, attacher.setEGID(456))
	require.Equal(t, []int{123, 123}, euidCalls)
	require.Equal(t, []int{456, 456}, egidCalls)
	require.True(t, attacher.initialized)
	require.True(t, attacher.terminated)
}

func TestTerminalCleanupCanRunRepeatedly(t *testing.T) {
	originalGetEUID := getEUID
	originalGetEGID := getEGID
	originalSetEUID := setEUID
	originalSetEGID := setEGID
	t.Cleanup(func() {
		getEUID = originalGetEUID
		getEGID = originalGetEGID
		setEUID = originalSetEUID
		setEGID = originalSetEGID
	})

	var euidCalls []int
	var egidCalls []int
	getEUID = func() int {
		return 123
	}
	getEGID = func() int {
		return 456
	}
	setEUID = func(id int) error {
		euidCalls = append(euidCalls, id)
		return nil
	}
	setEGID = func(id int) error {
		egidCalls = append(egidCalls, id)
		return nil
	}

	const attachID int64 = 1

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), attachID, func() int64 {
		return attachID
	})
	attacher.Init()
	require.NoError(t, attacher.Terminate())
	require.NoError(t, attacher.Cleanup())

	require.Equal(t, []int{123, 123}, euidCalls)
	require.Equal(t, []int{456, 456}, egidCalls)
	require.True(t, attacher.initialized)
	require.True(t, attacher.terminated)
}

func TestTerminalCleanupWinsBetweenCredentialChanges(t *testing.T) {
	originalGetEUID := getEUID
	originalGetEGID := getEGID
	originalSetEUID := setEUID
	originalSetEGID := setEGID
	t.Cleanup(func() {
		getEUID = originalGetEUID
		getEGID = originalGetEGID
		setEUID = originalSetEUID
		setEGID = originalSetEGID
	})

	var euidCalls []int
	var egidCalls []int
	getEUID = func() int {
		return 123
	}
	getEGID = func() int {
		return 456
	}
	setEUID = func(id int) error {
		euidCalls = append(euidCalls, id)
		return nil
	}
	setEGID = func(id int) error {
		egidCalls = append(egidCalls, id)
		return nil
	}

	const attachID int64 = 1

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), attachID, func() int64 {
		return attachID
	})
	attacher.Init()
	require.NoError(t, attacher.setEGID(987))
	require.NoError(t, attacher.Terminate())
	require.ErrorIs(t, attacher.setEUID(789), errTerminated)

	require.Equal(t, []int{123}, euidCalls)
	require.Equal(t, []int{987, 456}, egidCalls)
	require.True(t, attacher.terminated)
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
