// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package goversion parses Go toolchain versions.
package goversion // import "go.opentelemetry.io/obi/internal/goversion"

import (
	"fmt"
	stdlibversion "go/version"
	"strings"
)

// Version is a validated Go toolchain version.
type Version struct {
	value string
}

// Parse accepts an exact Go toolchain version with or without the go prefix.
func Parse(value string) (Version, error) {
	normalized := value
	if !strings.HasPrefix(normalized, "go") {
		normalized = "go" + normalized
	}
	if !stdlibversion.IsValid(normalized) {
		return Version{}, fmt.Errorf("invalid Go version %q", value)
	}
	return Version{value: normalized}, nil
}

// String returns the normalized, go-prefixed toolchain version.
func (v Version) String() string {
	return v.value
}

// Compare returns -1, 0, or +1 when v is less than, equal to, or greater than other.
func (v Version) Compare(other Version) int {
	return stdlibversion.Compare(v.value, other.value)
}
