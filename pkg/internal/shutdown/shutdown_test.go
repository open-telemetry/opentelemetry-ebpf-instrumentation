// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package shutdown

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	budget    = 50 * time.Millisecond
	eventual  = 5 * time.Second
	pollEvery = 5 * time.Millisecond
)

func TestBoundedOutlivesTheSignalUntilTheBudgetExpires(t *testing.T) {
	ctx, signal := context.WithCancel(t.Context())
	defer signal()
	ctx, cancelBudget := WithBudget(ctx, budget)
	defer cancelBudget()

	time.Sleep(2 * budget)
	bounded, cancel := Bounded(ctx, time.Hour)
	defer cancel()
	require.NoError(t, bounded.Err(), "the budget only starts counting at the signal")

	signal()
	require.NoError(t, bounded.Err())
	assert.Eventually(t, func() bool { return bounded.Err() != nil }, eventual, pollEvery)
}

func TestExportBudgetLeavesHeadroomBeforeTheShutdownTimeout(t *testing.T) {
	assert.Equal(t, 750*time.Millisecond, ExportBudget(time.Second))
	assert.Equal(t, 22500*time.Millisecond, ExportBudget(30*time.Second))
}

func TestWithExportBudgetReadsTheShutdownTimeoutAtTheSignal(t *testing.T) {
	ctx, signal := context.WithCancel(t.Context())
	defer signal()
	shutdownTimeout := time.Hour
	ctx, cancelBudget := WithExportBudget(ctx, func() time.Duration { return shutdownTimeout })
	defer cancelBudget()

	shutdownTimeout = 4 * budget
	signal()

	bounded, cancel := Bounded(ctx, time.Hour)
	defer cancel()
	require.NoError(t, bounded.Err())
	assert.Eventually(t, func() bool { return bounded.Err() != nil }, eventual, pollEvery)
}

func TestBoundedIsCappedByTheMaxTimeout(t *testing.T) {
	ctx, cancelBudget := WithBudget(t.Context(), time.Hour)
	defer cancelBudget()

	bounded, cancel := Bounded(ctx, budget)
	defer cancel()
	assert.Eventually(t, func() bool { return bounded.Err() != nil }, eventual, pollEvery)
}

func TestBoundedWithoutBudgetUsesTheMaxTimeout(t *testing.T) {
	ctx, signal := context.WithCancel(t.Context())
	signal()

	bounded, cancel := Bounded(ctx, time.Hour)
	defer cancel()
	require.NoError(t, bounded.Err())
	deadline, ok := bounded.Deadline()
	require.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(time.Hour), deadline, time.Minute)
}

func TestDrainsIdleWhenAllReadersEnded(t *testing.T) {
	drains := NewDrains()
	ctx := WithDrains(t.Context(), drains)
	assert.True(t, isClosed(drains.Idle()), "idle with no readers")

	endFirst := RegisterReader(ctx)
	endSecond := RegisterReader(ctx)
	idle := drains.Idle()
	assert.False(t, isClosed(idle))

	endFirst()
	endFirst()
	assert.False(t, isClosed(idle))

	endSecond()
	assert.True(t, isClosed(idle))
}

func TestRegisterReaderWithoutDrainsIsNoop(t *testing.T) {
	RegisterReader(t.Context())()
}

func TestWaitSettledWaitsForAReaderRegisteredDuringTheGrace(t *testing.T) {
	drains := NewDrains()
	ctx := WithDrains(t.Context(), drains)

	settled := make(chan struct{})
	go func() {
		drains.WaitSettled(budget, time.After(time.Hour))
		close(settled)
	}()

	endLate := RegisterReader(ctx)
	time.Sleep(4 * budget)
	assert.False(t, isClosed(settled), "a reader registered after the wait started must be waited for")

	endLate()
	assert.Eventually(t, func() bool { return isClosed(settled) }, eventual, pollEvery)
}

func TestWaitSettledGivesUp(t *testing.T) {
	drains := NewDrains()
	defer RegisterReader(WithDrains(t.Context(), drains))()

	settled := make(chan struct{})
	go func() {
		drains.WaitSettled(time.Hour, time.After(budget))
		close(settled)
	}()
	assert.Eventually(t, func() bool { return isClosed(settled) }, eventual, pollEvery)
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
