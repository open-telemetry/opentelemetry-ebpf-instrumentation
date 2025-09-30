// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package swarms

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestReadUntilInputClosed(t *testing.T) {
	input := make(chan int, 10)
	input <- 1
	input <- 2
	input <- 3
	input <- 4
	close(input)
	var output []int
	done := make(chan struct{})
	go func() {
		ForEachInput(t.Context(), input, nil, func(i int) {
			output = append(output, i)
		})
		close(done)
	}()
	testutil.ReadChannel(t, done, timeout)
	assert.Equal(t, []int{1, 2, 3, 4}, output)
}

func TestReadUntilContextClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	input := make(chan int, 10)
	input <- 1
	input <- 2
	input <- 3
	input <- 4
	mt := sync.RWMutex{}
	var output []int
	done := make(chan struct{})
	go func() {
		ForEachInput(ctx, input, nil, func(i int) {
			mt.Lock()
			defer mt.Unlock()
			output = append(output, i)
		})
		close(done)
	}()
	test.Eventually(t, timeout, func(t require.TestingT) {
		mt.RLock()
		defer mt.RUnlock()
		assert.Equal(t, []int{1, 2, 3, 4}, output)
	})
	cancel()
	testutil.ReadChannel(t, done, timeout)
}
