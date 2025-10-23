// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpirableLRU_PutGetRemove(t *testing.T) {
	lru := NewExpirableLRU[string, string](5 * time.Minute)

	lru.Put("foo", "bar")
	v, ok := lru.Get("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", v)
	assert.Equal(t, 1, lru.Len())

	v, ok = lru.Get("baz")
	assert.False(t, ok)
	assert.Empty(t, v)

	lru.Put("baz", "bae")
	v, ok = lru.Get("baz")
	assert.True(t, ok)
	assert.Equal(t, "bae", v)
	assert.Equal(t, 2, lru.Len())

	lru.Remove("foo")
	_, ok = lru.Get("foo")
	assert.False(t, ok)
	assert.Equal(t, 1, lru.Len())
}

func TestExpirableLRU_ExpireAll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := NewExpirableLRU[string, string](5 * time.Minute)

		// Add items at different times
		cache.Put("key1", "value1")
		// Advance time by 2 minutes
		time.Sleep(2 * time.Minute)
		cache.Put("key2", "value2")
		// Advance time by 2 more minutes (key1 is now 4 minutes old, key2 is 2 minutes old)
		time.Sleep(2 * time.Minute)
		cache.Put("key3", "value3")

		assert.Zero(t, cache.ExpireAll())

		// All items should be there(none have exceeded 5-minute TTL)
		assert.Equal(t, 3, cache.Len())

		v, ok := cache.Get("key1")
		require.True(t, ok, "Expected to find key1")
		assert.Equal(t, "value1", v)
		time.Sleep(2 * time.Minute)

		v, ok = cache.Get("key2")
		require.True(t, ok, "Expected to find key2")
		assert.Equal(t, "value2", v)
		time.Sleep(2 * time.Minute)

		v, ok = cache.Get("key3")
		require.True(t, ok, "Expected to find key3")
		assert.Equal(t, "value3", v)
		time.Sleep(2 * time.Minute)

		assert.Equal(t, 1, cache.ExpireAll())

		// key1 is 6 minutes old, should expire while others are still valid
		assert.Equal(t, 2, cache.Len())

		_, ok = cache.Get("key1")
		assert.False(t, ok, "Expected key1 to be expired")
		v, ok = cache.Get("key2")
		require.True(t, ok, "Expected to find key2")
		assert.Equal(t, "value2", v)
		v, ok = cache.Get("key3")
		require.True(t, ok, "Expected to find key3")
		assert.Equal(t, "value3", v)

		// Advance age by two minute:
		//   - "key1": removed (expired)
		//   - "key2": 6 minutes old
		//   - "key3": 4 minutes old
		time.Sleep(2 * time.Minute)

		// add key 4
		cache.Put("key4", "value4")
		// Advance age by four minute:
		//   - "key1": removed (expired)
		//   - "key2": 10 minutes old
		//   - "key3": 8 minutes old
		//   - "key4": 2 minutes old
		time.Sleep(4 * time.Minute)

		// all the keys but key4 should be expired
		assert.Equal(t, 2, cache.ExpireAll())
		assert.Equal(t, 1, cache.Len())

		_, ok = cache.Get("key1")
		assert.False(t, ok, "Expected key1 to be expired")
		_, ok = cache.Get("key2")
		assert.False(t, ok, "Expected key2 to be expired")
		_, ok = cache.Get("key3")
		assert.False(t, ok, "Expected key3 to be expired")
		v, ok = cache.Get("key4")
		require.True(t, ok, "Expected to find key4")
		assert.Equal(t, "value4", v)

		// Advance age by four minute:
		//   - "key1": removed (expired)
		//   - "key2": removed (expired)
		//   - "key3": removed (expired)
		//   - "key4": 6 minutes old
		time.Sleep(4 * time.Minute)

		// a re-added key should not expire
		cache.Put("key1", "value1")
		// Advance age by two minute:
		//   - "key1": two minutes old
		//   - "key2": removed (expired)
		//   - "key3": removed (expired)
		//   - "key4": 10 minutes old
		time.Sleep(2 * time.Minute)

		assert.Equal(t, 1, cache.ExpireAll())

		assert.Equal(t, 1, cache.Len())
		v, ok = cache.Get("key1")
		require.True(t, ok, "Expected to find key1")
		assert.Equal(t, "value1", v)
		_, ok = cache.Get("key2")
		assert.False(t, ok, "Expected key2 to be expired")
		_, ok = cache.Get("key3")
		assert.False(t, ok, "expected key 3 to be expired")
		_, ok = cache.Get("key4")
		assert.False(t, ok, "expected key 4 to be expired")
	})
}

func TestWithEvictCallBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var evictedKeys []int
		var evictedVals []string
		cache := NewExpirableLRU[int, string](5*time.Minute,
			WithEvictCallBack(func(k int, v string) {
				evictedKeys = append(evictedKeys, k)
				evictedVals = append(evictedVals, v)
			}))

		cache.Put(1, "one")
		time.Sleep(1 * time.Minute)
		cache.Put(2, "two")
		time.Sleep(2 * time.Minute)
		cache.Put(3, "three")

		assert.Zero(t, cache.ExpireAll())
		assert.Empty(t, evictedKeys)
		assert.Empty(t, evictedVals)

		time.Sleep(4 * time.Minute)

		assert.Equal(t, 2, cache.ExpireAll())
		assert.Equal(t, []int{1, 2}, evictedKeys)
		assert.Equal(t, []string{"one", "two"}, evictedVals)
	})
}

func TestPutAlsoUpdatesTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := NewExpirableLRU[int, string](5 * time.Minute)
		cache.Put(1, "one")

		time.Sleep(3 * time.Minute)
		cache.Put(2, "two")

		assert.Zero(t, cache.ExpireAll())

		time.Sleep(3 * time.Minute)
		cache.Put(1, "another")
		time.Sleep(3 * time.Minute)

		assert.Equal(t, 1, cache.ExpireAll())
		assert.Equal(t, 1, cache.Len())
		_, ok := cache.Get(1)
		assert.True(t, ok, "Expected to find key1")
		_, ok = cache.Get(2)
		assert.False(t, ok, "Expected key2 to be expired")
	})
}
