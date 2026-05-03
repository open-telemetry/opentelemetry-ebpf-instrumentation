// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package example

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorrectUsage(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.NoError(ct, nil)
		require.Equal(ct, 1, 1)
		assert.Less(ct, 1, 2)
	}, time.Minute, time.Second)
}

func TestBuggyUsage(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.Len(t, []int{1}, 1)  // want `use ct instead of t inside EventuallyWithT callback`
		require.NotEmpty(t, "hello") // want `use ct instead of t inside EventuallyWithT callback`
		assert.Less(t, 1, 2)        // want `use ct instead of t inside EventuallyWithT callback`
		require.Equal(ct, 1, 1)     // this is fine
	}, time.Minute, time.Second)
}

func TestMixedUsage(t *testing.T) {
	// Assertions outside EventuallyWithT are fine.
	require.NoError(t, nil)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.Equal(ct, 1, 1)
		require.Len(t, []int{}, 0) // want `use ct instead of t inside EventuallyWithT callback`
	}, time.Minute, time.Second)

	// Also fine — outside the callback.
	require.Equal(t, 1, 1)
}

func TestDifferentParamName(t *testing.T) {
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		require.Equal(t, 1, 1) // want `use collect instead of t inside EventuallyWithT callback`
		assert.Equal(collect, 1, 1)
	}, time.Minute, time.Second)
}

func TestShadowedT(t *testing.T) {
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		require.Equal(t, 1, 1) // no diagnostic — t is the CollectT param, not the outer *testing.T
		assert.Less(t, 1, 2)
	}, time.Minute, time.Second)
}

func TestAssertEventuallyWithT(t *testing.T) {
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.Equal(t, 1, 1) // want `use ct instead of t inside EventuallyWithT callback`
		assert.Equal(ct, 1, 1)
	}, time.Minute, time.Second)
}
