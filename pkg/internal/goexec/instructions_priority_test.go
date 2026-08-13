// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestedFunctionNamePrefersExactName(t *testing.T) {
	functions := map[string]struct{}{
		"golang.org/x/net/http2/hpack.(*Encoder).WriteField": {},
	}

	name, exact, ok := requestedFunctionName(
		"golang.org/x/net/http2/hpack.(*Encoder).WriteField", functions)
	require.True(t, ok)
	assert.True(t, exact)
	assert.Equal(t, "golang.org/x/net/http2/hpack.(*Encoder).WriteField", name)
}

func TestRequestedFunctionNameFallsBackToVendorAlias(t *testing.T) {
	functions := map[string]struct{}{
		"golang.org/x/net/http2/hpack.(*Encoder).WriteField": {},
	}

	name, exact, ok := requestedFunctionName(
		"example.com/module/vendor/golang.org/x/net/http2/hpack.(*Encoder).WriteField", functions)
	require.True(t, ok)
	assert.False(t, exact)
	assert.Equal(t, "golang.org/x/net/http2/hpack.(*Encoder).WriteField", name)
}

func TestStoreFunctionOffsetExactNameWinsInEitherOrder(t *testing.T) {
	const name = "golang.org/x/net/http2/hpack.(*Encoder).WriteField"
	alias := FuncOffsets{Start: 1}
	exact := FuncOffsets{Start: 2}

	for _, order := range []struct {
		name       string
		candidates []struct {
			offsets FuncOffsets
			isExact bool
		}
	}{
		{
			name: "alias before exact",
			candidates: []struct {
				offsets FuncOffsets
				isExact bool
			}{{alias, false}, {exact, true}},
		},
		{
			name: "exact before alias",
			candidates: []struct {
				offsets FuncOffsets
				isExact bool
			}{{exact, true}, {alias, false}},
		},
	} {
		t.Run(order.name, func(t *testing.T) {
			allOffsets := map[string]FuncOffsets{}
			selectedIsExact := map[string]bool{}
			for _, candidate := range order.candidates {
				storeFunctionOffset(allOffsets, selectedIsExact, name, candidate.offsets, candidate.isExact)
			}

			assert.Equal(t, exact, allOffsets[name])
			assert.True(t, selectedIsExact[name])
		})
	}
}

func TestStoreFunctionOffsetKeepsFirstAliasFallback(t *testing.T) {
	const name = "golang.org/x/net/http2/hpack.(*Encoder).WriteField"
	allOffsets := map[string]FuncOffsets{}
	selectedIsExact := map[string]bool{}

	storeFunctionOffset(allOffsets, selectedIsExact, name, FuncOffsets{Start: 1}, false)
	storeFunctionOffset(allOffsets, selectedIsExact, name, FuncOffsets{Start: 2}, false)

	assert.Equal(t, uint64(1), allOffsets[name].Start)
	assert.False(t, selectedIsExact[name])
}
