// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpiryMap_ZeroTTLExpiresImmediately(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	em := NewExpiryMap[string](clock, 0)

	em.GetOrCreate([]string{"label1", "value1"}, func() string { return "entry1" })
	em.GetOrCreate([]string{"label2", "value2"}, func() string { return "entry2" })

	// Advance time by any amount
	now = now.Add(1 * time.Nanosecond)

	expired := em.DeleteExpired()
	assert.Len(t, expired, 2, "TTL=0 should expire entries immediately")
	assert.Contains(t, expired, "entry1")
	assert.Contains(t, expired, "entry2")

	// Verify entries are gone
	val1 := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "new_entry1" })
	val2 := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "new_entry2" })
	assert.Equal(t, "new_entry1", val1)
	assert.Equal(t, "new_entry2", val2)
}

func TestExpiryMap_ZeroTTLBoundsHighCardinality(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	em := NewExpiryMap[int](clock, 0)

	for i := range 1000 {
		em.GetOrCreate([]string{fmt.Sprintf("label_%d", i)}, func() int { return i })
	}

	now = now.Add(1 * time.Nanosecond)
	expired := em.DeleteExpired()
	assert.Len(t, expired, 1000)
	assert.Empty(t, em.All(), "All entries should be evicted with TTL=0")
}

func TestExpiryMap_NormalExpiration(t *testing.T) {
	// Mock clock that we can control
	now := time.Now()
	clock := func() time.Time { return now }

	// Create expiry map with TTL=5 minutes
	em := NewExpiryMap[string](clock, 5*time.Minute)

	// Add some entries
	val1 := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "entry1" })
	val2 := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "entry2" })

	assert.Equal(t, "entry1", val1)
	assert.Equal(t, "entry2", val2)

	// Advance time beyond TTL
	now = now.Add(10 * time.Minute)

	// Delete expired entries - should return the expired entries
	expired := em.DeleteExpired()
	assert.Len(t, expired, 2, "Both entries should expire after 10 minutes with TTL=5 minutes")
	assert.Contains(t, expired, "entry1")
	assert.Contains(t, expired, "entry2")

	// Verify entries are gone - should create new ones
	val1Again := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "new_entry1" })
	val2Again := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "new_entry2" })

	assert.Equal(t, "new_entry1", val1Again)
	assert.Equal(t, "new_entry2", val2Again)
}
