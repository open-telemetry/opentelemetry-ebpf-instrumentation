// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !amd64

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"errors"
)

// resolveGOMAXPROCSFromCode reports that instruction-based global recovery is
// unsupported on this architecture. Symbol-based resolution uses a separate path.
func resolveGOMAXPROCSFromCode(_ *elf.File, _ uint64, _ []byte) (uint64, error) {
	return 0, errors.New("stripped Go runtime global address recovery requires amd64")
}

// resolveRuntimeMetricReceiverFromCode reports that receiver recovery requires
// the amd64 instruction matcher.
func resolveRuntimeMetricReceiverFromCode(_ uint64, _ []byte, _ ...uint64) (uint64, error) {
	return 0, errors.New("stripped Go runtime global address recovery requires amd64")
}
