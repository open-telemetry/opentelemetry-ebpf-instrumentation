// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGCEventOrderWatermark(t *testing.T) {
	var order gcEventOrder
	later := gcRuntimeEvent{timestamp: 30, threadID: 1}
	earlier := gcRuntimeEvent{timestamp: 10, threadID: 2}
	boundary := gcRuntimeEvent{timestamp: 20, threadID: 2}
	for _, event := range []gcRuntimeEvent{later, earlier, boundary} {
		require.NoError(t, order.add(event))
	}
	first, err := order.releaseBefore(20)
	require.NoError(t, err)
	require.Equal(t, []gcRuntimeEvent{earlier}, first)
	second, err := order.releaseBefore(31)
	require.NoError(t, err)
	require.Equal(t, []gcRuntimeEvent{boundary, later}, second)
	require.Empty(t, order.pending)
	require.NoError(t, order.add(gcRuntimeEvent{timestamp: 40}))
	require.Equal(t, []gcRuntimeEvent{earlier}, first, "queue reuse preserves released values")
	require.Equal(t, []gcRuntimeEvent{boundary, later}, second)
}

func TestGCEventOrderSameThreadTie(t *testing.T) {
	var order gcEventOrder
	start := gcRuntimeEvent{timestamp: 10, threadID: 1, eventID: clrGCStartEventID}
	end := gcRuntimeEvent{timestamp: 10, threadID: 1, eventID: clrGCEndEventID}
	require.NoError(t, order.add(start))
	require.NoError(t, order.add(end))
	events, err := order.releaseBefore(11)
	require.NoError(t, err)
	require.Equal(t, []gcRuntimeEvent{start, end}, events)
}

func TestGCEventOrderRejectsAmbiguousTie(t *testing.T) {
	var order gcEventOrder
	require.NoError(t, order.add(gcRuntimeEvent{timestamp: 10, threadID: 1}))
	events, err := order.releaseBefore(10)
	require.NoError(t, err)
	require.Empty(t, events, "the watermark does not close its own timestamp")
	require.NoError(t, order.add(gcRuntimeEvent{timestamp: 10, threadID: 2}))
	events, err = order.releaseBefore(11)
	require.ErrorContains(t, err, "ambiguous")
	require.Empty(t, events, "ambiguous events must not reach the assembler")
}

func TestGCEventOrderLimit(t *testing.T) {
	var order gcEventOrder
	for timestamp := range maximumPendingGCEvents {
		require.NoError(t, order.add(gcRuntimeEvent{timestamp: int64(timestamp)}))
	}
	require.ErrorContains(t, order.add(gcRuntimeEvent{}), "limit")
	require.Len(t, order.pending, maximumPendingGCEvents)
	events, err := order.releaseBefore(maximumPendingGCEvents)
	require.NoError(t, err)
	require.Len(t, events, maximumPendingGCEvents)
	require.NoError(t, order.add(gcRuntimeEvent{timestamp: maximumPendingGCEvents}))
}

func TestGCEventOrderFinish(t *testing.T) {
	var order gcEventOrder
	event := gcRuntimeEvent{timestamp: math.MaxInt64, threadID: 1}
	require.NoError(t, order.add(event))
	events, err := order.finish()
	require.NoError(t, err)
	require.Equal(t, []gcRuntimeEvent{event}, events, "clean completion includes the final timestamp")
	require.Empty(t, order.pending)
	require.NoError(t, order.add(event))
	event.threadID = 2
	require.NoError(t, order.add(event))
	events, err = order.finish()
	require.ErrorContains(t, err, "ambiguous")
	require.Empty(t, events)
}
