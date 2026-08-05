// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"syscall"
)

var errUnsupported = errors.New("jvmtools attach is only supported on linux")

type JAttacher struct{}

func NewJAttacher(_ *slog.Logger) *JAttacher {
	return &JAttacher{}
}

func (*JAttacher) Init() {}

func (*JAttacher) Cleanup() error {
	return nil
}

func (*JAttacher) Attach(
	_ int,
	_ []string,
	_ bool,
	_ func(syscall.Signal) error,
) (io.ReadCloser, error) {
	return nil, errUnsupported
}

func (*JAttacher) AttachContext(
	_ context.Context,
	_ int,
	_ []string,
	_ bool,
	_ func(syscall.Signal) error,
) (io.ReadCloser, error) {
	return nil, errUnsupported
}
