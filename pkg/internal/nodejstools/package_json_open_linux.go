// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejstools // import "go.opentelemetry.io/obi/pkg/internal/nodejstools"

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openPackageJSON(path string) (*os.File, bool) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return nil, false
		}
		return nil, true
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, true
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size > maxPackageJSONBytes {
		unix.Close(fd)
		return nil, true
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, true
	}
	return file, true
}
