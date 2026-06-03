// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package harvest

import "os"

func openJSFileForScan(path string) (*os.File, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxJSFileScanBytes {
		return nil, false, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	info, err = file.Stat()
	if err != nil {
		file.Close()
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxJSFileScanBytes {
		file.Close()
		return nil, false, nil
	}
	return file, true, nil
}
