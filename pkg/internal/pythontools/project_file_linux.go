// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openProjectFile(path string) (*os.File, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return nil, false, nil
		}
		return nil, true, err
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, true, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, true, fmt.Errorf("project metadata file %s is not regular", path)
	}
	if stat.Size > maxProjectFileBytes {
		unix.Close(fd)
		return nil, true, fmt.Errorf("project metadata file %s exceeds %d bytes", path, maxProjectFileBytes)
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, true, fmt.Errorf("opening project metadata file %s", path)
	}
	return file, true, nil
}
