// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
)

func TestCriteriaUpdatesReplacePrefersCompletedResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result error
	}{
		{name: "applied"},
		{name: "rejected", result: errors.New("incompatible selection")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				initial := []Selector{&GlobAttributes{PIDs: []uint32{10}}}
				next := []Selector{&GlobAttributes{PIDs: []uint32{20}}}
				updates := NewCriteriaUpdates(initial, nil)
				defer updates.Stop()
				base, cancel := context.WithCancel(t.Context())
				defer cancel()
				ctx := &blockedCancellationContext{
					Context: base, errRead: make(chan struct{}), resume: make(chan struct{}),
				}
				result := make(chan error, 1)
				go func() { result <- updates.Replace(ctx, next, nil) }()
				request := <-updates.Requests()

				// Complete after cancellation is selected, before Replace returns it.
				cancel()
				<-ctx.errRead
				updates.Complete(request, tc.result)
				close(ctx.resume)
				require.ErrorIs(t, <-result, tc.result)
				current, _ := updates.Current()
				if tc.result == nil {
					require.Equal(t, next, current)
				} else {
					require.Equal(t, initial, current)
				}
			})
		})
	}
}

type blockedCancellationContext struct {
	context.Context
	errRead chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *blockedCancellationContext) Err() error {
	c.once.Do(func() { close(c.errRead) })
	<-c.resume
	return c.Context.Err()
}
