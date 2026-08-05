// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package exec // import "go.opentelemetry.io/obi/pkg/appolly/discover/exec"

import (
	"os"

	"golang.org/x/sys/unix"
)

// DuplicateProcessRoot returns an independently owned copy of the
// discovery-time process handle without transferring the original.
func (fi *FileInfo) DuplicateProcessRoot() *os.File {
	if fi == nil {
		return nil
	}
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	if fi.processRoot == nil {
		return nil
	}
	fd, err := unix.Dup(int(fi.processRoot.Fd()))
	if err != nil {
		return nil
	}
	unix.CloseOnExec(fd)
	root := os.NewFile(uintptr(fd), fi.processRoot.Name())
	if root == nil {
		_ = unix.Close(fd)
	}
	return root
}
