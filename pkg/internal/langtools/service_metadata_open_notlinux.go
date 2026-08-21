// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package langtools // import "go.opentelemetry.io/obi/pkg/internal/langtools"

import "os"

func OpenServiceMetadataFile(path string, _ int64) (*os.File, bool) {
	_, err := os.Lstat(path)
	return nil, !os.IsNotExist(err)
}
