// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolverAnalysisCacheCachesImageResults(t *testing.T) {
	tests := []struct {
		name    string
		result  *elfAnalysis
		err     error
		wantErr error
	}{
		{name: "success", result: &elfAnalysis{anchor: 42}},
		{name: "runtime not found", err: errRuntimeNotFound, wantErr: errRuntimeNotFound},
		{
			name:    "unsupported layout",
			err:     errors.Join(errUnsupportedLayout, errors.New("unknown version")),
			wantErr: errUnsupportedLayout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := newResolverAnalysisCache()
			calls := 0
			analyze := func() (*elfAnalysis, error) {
				calls++
				return tt.result, tt.err
			}

			first, firstErr := cache.getOrAnalyze(mappedObjectKey{device: 1, inode: 2}, analyze)
			second, secondErr := cache.getOrAnalyze(mappedObjectKey{device: 1, inode: 2}, analyze)

			assert.Same(t, tt.result, first)
			assert.Same(t, first, second)
			require.ErrorIs(t, firstErr, tt.wantErr)
			require.ErrorIs(t, secondErr, tt.wantErr)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestResolverAnalysisCacheRetriesOperationalErrors(t *testing.T) {
	cache := newResolverAnalysisCache()
	calls := 0
	analyze := func() (*elfAnalysis, error) {
		calls++
		return nil, os.ErrPermission
	}

	_, firstErr := cache.getOrAnalyze(mappedObjectKey{device: 1, inode: 2}, analyze)
	_, secondErr := cache.getOrAnalyze(mappedObjectKey{device: 1, inode: 2}, analyze)

	require.ErrorIs(t, firstErr, os.ErrPermission)
	require.ErrorIs(t, secondErr, os.ErrPermission)
	assert.Equal(t, 2, calls)
}
