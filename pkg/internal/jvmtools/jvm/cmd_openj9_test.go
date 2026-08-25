// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"context"
	"errors"
	"log/slog"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNewJ9AttacherUsesNegativeFDSentinel(t *testing.T) {
	attacher := newJ9Attacher(slog.Default())

	if fd := attacher.fd.Load(); fd >= 0 {
		t.Fatalf("expected negative fd sentinel, got %d", fd)
	}
}

func TestWriteCommandPreservesSyscallError(t *testing.T) {
	err := writeCommand(-1, "ATTACH_DETACHED")

	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("expected EBADF, got %v", err)
	}
}

func TestJ9ReaderReadReturnsZeroCountOnSyscallError(t *testing.T) {
	attacher := newJ9Attacher(slog.Default())
	attacher.fd.Store(1 << 30)

	n, err := (&j9Reader{attacher: attacher}).Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("expected zero byte count, got %d", n)
	}
	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("expected EBADF, got %v", err)
	}
}

func TestJ9ReaderCloseStopsOnContextCancellation(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fds[1]) })

	attacher := newJ9Attacher(slog.Default())
	attacher.fd.Store(int32(fds[0]))
	ctx, cancel := context.WithCancel(context.Background())
	reader := &j9Reader{attacher: attacher, ctx: ctx}

	done := make(chan error, 1)
	go func() { done <- reader.Close() }()

	command := make([]byte, len("ATTACH_DETACHED")+1)
	_, err = unix.Read(fds[1], command)
	require.NoError(t, err)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop the OpenJ9 detach response read")
	}
}

func TestCleanupStopsOnContextCancellationAndRestoresCredentials(t *testing.T) {
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

	getEUID = func() int { return 123 }
	getEGID = func() int { return 456 }
	var restoredEUID, restoredEGID int
	setEUID = func(id int) error {
		restoredEUID = id
		return nil
	}
	setEGID = func(id int) error {
		restoredEGID = id
		return nil
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fds[1]) })

	attacher := NewJAttacher(slog.Default(), 1, alwaysRunForCurrentAttach)
	attacher.Init()
	attacher.j9attacher = newJ9Attacher(slog.Default())
	attacher.j9attacher.fd.Store(int32(fds[0]))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- attacher.Cleanup(ctx) }()

	command := make([]byte, len("ATTACH_DETACHED")+1)
	n, err := unix.Read(fds[1], command)
	require.NoError(t, err)
	require.Equal(t, len(command), n)
	require.Equal(t, "ATTACH_DETACHED\x00", string(command))
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop OpenJ9 cleanup")
	}

	require.Equal(t, 123, restoredEUID)
	require.Equal(t, 456, restoredEGID)
}
