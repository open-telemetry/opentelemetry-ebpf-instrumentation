// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package split provides a generic Iterator for zero-copy splitting of
// strings and byte slices.
package split // import "go.opentelemetry.io/obi/pkg/internal/split"
import (
	"bytes"
	"strings"
)

// CutByte is a single-byte-separator alternative to bytes.Cut. It's
// around 15-20% faster than bytes.Cut.
func CutByte(s []byte, sep byte) (before, after []byte, found bool) {
	if i := bytes.IndexByte(s, sep); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, nil, false
}

// StringsCutByte is a single-byte-separator alternative to strings.Cut. It's
// around 30% faster than strings.Cut.
func StringsCutByte(s string, sep byte) (before, after string, found bool) {
	if i := strings.IndexByte(s, sep); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}
