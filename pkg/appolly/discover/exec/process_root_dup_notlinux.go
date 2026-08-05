// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package exec // import "go.opentelemetry.io/obi/pkg/appolly/discover/exec"

import "os"

// DuplicateProcessRoot fails closed where proc-directory descriptors are not
// supported.
func (*FileInfo) DuplicateProcessRoot() *os.File {
	return nil
}
