// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

// TestProcessNotFound tests that InspectOffsets process exits on context cancellation
// even if the target process wasn't found
func TestProcessNotFound(t *testing.T) {
	finish := make(chan struct{})
	go func() {
		defer close(finish)
		if _, err := InspectOffsets(nil, nil); err == nil {
			t.Log("was expecting error in InspectOffsets")
		}
	}()
	testutil.ReadChannel(t, finish, 5*time.Second)
}

func TestOffsets_HasGoChannelOffsets(t *testing.T) {
	assert.False(t, (*Offsets)(nil).HasGoChannelOffsets())
	assert.False(t, (&Offsets{}).HasGoChannelOffsets())
	assert.False(t, (&Offsets{Field: FieldOffsets{
		HchanDataqsizPos: uint64(8),
		HchanSendxPos:    uint64(48),
	}}).HasGoChannelOffsets())
	assert.False(t, (&Offsets{Field: FieldOffsets{
		HchanDataqsizPos: uint64(8),
		HchanSendxPos:    uint64(48),
		HchanRecvxPos:    int64(56),
	}}).HasGoChannelOffsets())
	assert.True(t, (&Offsets{Field: FieldOffsets{
		HchanDataqsizPos: uint64(8),
		HchanSendxPos:    uint64(48),
		HchanRecvxPos:    uint64(56),
	}}).HasGoChannelOffsets())
}
