// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"errors"
	"os"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type nativeGoAutoSDKProcessAccess struct{}

func newGoAutoSDKProcessAccess() goAutoSDKProcessAccess {
	return nativeGoAutoSDKProcessAccess{}
}

func (nativeGoAutoSDKProcessAccess) Open(
	*os.File,
	*exec.FileInfo,
) (goAutoSDKProcessSession, error) {
	return nil, errors.New("process access is unavailable")
}

func goAutoSDKProcessGone(error) bool {
	return false
}
