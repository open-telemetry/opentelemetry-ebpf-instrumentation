// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"errors"
	"log/slog"
	"syscall"
	"testing"
)

func TestNewJ9AttacherUsesNegativeFDSentinel(t *testing.T) {
	attacher := newJ9Attacher(slog.Default())

	if attacher.fd >= 0 {
		t.Fatalf("expected negative fd sentinel, got %d", attacher.fd)
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
	attacher.fd = 1 << 30

	n, err := (&j9Reader{attacher: attacher}).Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("expected zero byte count, got %d", n)
	}
	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("expected EBADF, got %v", err)
	}
}
