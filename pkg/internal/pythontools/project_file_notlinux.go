// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"fmt"
	"os"
)

func openProjectFile(path string) (*os.File, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, true, fmt.Errorf("project metadata file %s is not regular", path)
	}
	if info.Size() > maxProjectFileBytes {
		return nil, true, fmt.Errorf("project metadata file %s exceeds %d bytes", path, maxProjectFileBytes)
	}
	file, err := os.Open(path)
	return file, true, err
}
