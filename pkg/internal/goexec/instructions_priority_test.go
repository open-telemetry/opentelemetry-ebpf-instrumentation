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

func TestStoreFunctionOffsetRetainsEveryCopyInTraversalIndependentOrder(t *testing.T) {
	const name = "golang.org/x/net/http2/hpack.(*Encoder).WriteField"
	alias := FuncOffsets{Symbol: "example.com/module/vendor/" + name, Start: 1}
	exact := FuncOffsets{Symbol: name, Start: 2}

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
			allOffsets := map[string][]FuncOffsets{}
			for _, candidate := range order.candidates {
				storeFunctionOffset(allOffsets, name, candidate.offsets)
			}

			assert.Equal(t, []FuncOffsets{alias, exact}, allOffsets[name])
		})
	}
}

func TestStoreFunctionOffsetRetainsMultipleAliases(t *testing.T) {
	const name = "golang.org/x/net/http2/hpack.(*Encoder).WriteField"
	allOffsets := map[string][]FuncOffsets{}
	first := FuncOffsets{Symbol: "one/vendor/" + name, Start: 1}
	second := FuncOffsets{Symbol: "two/vendor/" + name, Start: 2}

	storeFunctionOffset(allOffsets, name, second)
	storeFunctionOffset(allOffsets, name, first)

	assert.Equal(t, []FuncOffsets{first, second}, allOffsets[name])
}

func TestStoreFunctionOffsetDeduplicatesAttachmentOffsets(t *testing.T) {
	const name = "golang.org/x/net/http2/hpack.(*Encoder).WriteField"
	allOffsets := map[string][]FuncOffsets{}

	storeFunctionOffset(allOffsets, name, FuncOffsets{
		Symbol: "z/vendor/" + name, Start: 1, Returns: []uint64{4, 3}, CallTargets: []uint64{9, 8},
		PadStart: 6, PadOffset: 7,
	})
	storeFunctionOffset(allOffsets, name, FuncOffsets{
		Symbol: "a/vendor/" + name, Start: 1, Returns: []uint64{3, 5}, CallTargets: []uint64{8, 10},
	})

	require.Len(t, allOffsets[name], 1)
	assert.Equal(t, "a/vendor/"+name, allOffsets[name][0].Symbol)
	assert.Equal(t, []uint64{3, 4, 5}, allOffsets[name][0].Returns)
	assert.Equal(t, []uint64{8, 9, 10}, allOffsets[name][0].CallTargets)
	assert.Equal(t, uint64(6), allOffsets[name][0].PadStart)
	assert.Equal(t, uint64(7), allOffsets[name][0].PadOffset)
}

func TestStoreFunctionOffsetKeepsCanonicalIdentityWhenOffsetsMatch(t *testing.T) {
	const name = "golang.org/x/net/http2/hpack.(*Encoder).WriteField"
	allOffsets := map[string][]FuncOffsets{}

	storeFunctionOffset(allOffsets, name, FuncOffsets{Symbol: "a/vendor/" + name, Start: 1})
	storeFunctionOffset(allOffsets, name, FuncOffsets{Symbol: name, Start: 1})

	require.Len(t, allOffsets[name], 1)
	assert.Equal(t, name, allOffsets[name][0].Symbol)
}
