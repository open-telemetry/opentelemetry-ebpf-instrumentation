// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !obi_frida || !linux || (!amd64 && !arm64)

package core // import "go.opentelemetry.io/obi/pkg/internal/frida/core"

import (
	"context"
	"errors"
)

// Session is the unavailable native session in the default build.
type Session struct{ sessionState }

type Engine struct {
	post func(uintptr, string, uintptr)
}

func Open(context.Context, string) (*Engine, error) {
	return nil, errors.New("frida requires a Linux amd64/arm64 OBI build with -tags=obi_frida")
}

func (*Engine) Attach(context.Context, uint32, string) (*Session, error) {
	return nil, errors.New("frida backend unavailable")
}
func (*Engine) Close() error      { return nil }
func (*Session) Close(bool) error { return nil }
