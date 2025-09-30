// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"
	"time"

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
