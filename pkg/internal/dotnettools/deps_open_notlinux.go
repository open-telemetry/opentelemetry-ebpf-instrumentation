// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package dotnettools // import "go.opentelemetry.io/obi/pkg/internal/dotnettools"

import "os"

func openDepsJSON(_ string) *os.File {
	return nil
}
