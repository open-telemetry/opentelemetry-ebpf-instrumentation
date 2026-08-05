// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"os"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type identityStableProcessHandle struct{}

func openIdentityStableProcessHandle(int) (*identityStableProcessHandle, error) {
	return nil, errors.New("identity-stable process handles are unsupported")
}

func (*identityStableProcessHandle) Signal(syscall.Signal) error {
	return errors.New("identity-stable process signaling is unsupported")
}

func (*identityStableProcessHandle) Close() error { return nil }

func livePendingProcessIdentityMatches(*exec.FileInfo, *os.File) bool {
	return false
}

func executablePathThroughProcessRoot(*os.File) (string, error) {
	return "", errors.New("process-root executable paths are unsupported")
}

func filesystemRootPathThroughProcessRoot(*os.File) (string, error) {
	return "", errors.New("process-root filesystem paths are unsupported")
}
