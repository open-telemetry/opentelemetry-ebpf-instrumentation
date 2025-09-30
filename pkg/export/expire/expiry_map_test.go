// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpiryMap_DisableExpiration(t *testing.T) {
	// Mock clock that we can control
	now := time.Now()
	clock := func() time.Time { return now }

	// Create expiry map with TTL=0 (should disable expiration)
	em := NewExpiryMap[string](clock, 0)

	// Add some entries
	val1 := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "entry1" })
	val2 := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "entry2" })

	assert.Equal(t, "entry1", val1)
	assert.Equal(t, "entry2", val2)

	// Advance time significantly (would normally cause expiration)
	now = now.Add(10 * time.Hour)

	// Try to delete expired entries - should return empty slice when TTL=0
	expired := em.DeleteExpired()
	assert.Empty(t, expired, "No entries should expire when TTL=0")

	// Verify entries are still there
	val1Again := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "should_not_be_called" })
	val2Again := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "should_not_be_called" })

	assert.Equal(t, "entry1", val1Again)
	assert.Equal(t, "entry2", val2Again)
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
