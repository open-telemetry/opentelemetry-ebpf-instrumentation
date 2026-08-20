// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dotnettools // import "go.opentelemetry.io/obi/pkg/internal/dotnettools"

import (
	"os"

	"golang.org/x/sys/unix"
)

func openDepsJSON(path string) *os.File {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Size > maxDepsJSONBytes {
		unix.Close(fd)
		return nil
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
	}
	return file
}
