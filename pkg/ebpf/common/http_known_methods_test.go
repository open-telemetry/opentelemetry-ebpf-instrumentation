// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtraHTTPMethodConstants(t *testing.T) {
	constants := extraHTTPMethodConstants([]string{"GET", "PURGE", "PROPFIND", "purge", "INVALID METHOD", "TOO-LONG-METHOD"})
	assert.Equal(t, uint32(3), constants["extra_http_method_count"])
	methods := constants["extra_http_methods"].([maxExtraHTTPMethods]extraHTTPMethod)
	for i, want := range []string{"PURGE", "PROPFIND", "purge"} {
		require.Equal(t, uint8(len(want)), methods[i].Len)
		assert.Equal(t, want, string(methods[i].Name[:methods[i].Len]))
	}
}

func TestExtraHTTPMethodsLimit(t *testing.T) {
	methods := make([]string, maxExtraHTTPMethods+1)
	for i := range methods {
		methods[i] = "PURGE"
	}
	constants := extraHTTPMethodConstants(methods)
	assert.Equal(t, uint32(maxExtraHTTPMethods), constants["extra_http_method_count"])
}
