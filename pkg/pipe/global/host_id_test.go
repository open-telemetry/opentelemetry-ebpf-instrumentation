// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFetchTimeout(t *testing.T) {
	ctxInfo := ContextInfo{}
	start := time.Now()
	ctxInfo.FetchHostID(t.Context(), time.Millisecond)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, time.Second)
}
