// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package nodejstools // import "go.opentelemetry.io/obi/pkg/internal/nodejstools"

import "os"

func openPackageJSON(path string) (*os.File, bool) {
	_, err := os.Lstat(path)
	return nil, !os.IsNotExist(err)
}
