// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package img // import "go.opentelemetry.io/obi/internal/test/tools/img"

import "strings"

// Docker provides Repository and Tag helper methods for a complete image coordinates.
// It aims facilitating auto-update of image numbers and pinned digests from Renovate
type Docker string

func (d Docker) sepIndex() int {
	s := string(d)
	colon := strings.IndexByte(s, ':')
	at := strings.IndexByte(s, '@')
	switch {
	case colon == -1:
		return at
	case at == -1:
		return colon
	default:
		return min(colon, at)
	}
}

func (d Docker) Repository() string {
	i := d.sepIndex()
	if i == -1 {
		return string(d)
	}
	return string(d[:i])
}

func (d Docker) Tag() string {
	i := d.sepIndex()
	if i == -1 {
		return ""
	}
	return string(d[i+1:])
}
