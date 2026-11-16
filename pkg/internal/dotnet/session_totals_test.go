// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestExceptionSessionTotalsReconnect(t *testing.T) {
	totals := cumulativeSessionTotals{exceptions: map[string]uint64{"Failure": 10, "Quiet": 4}}
	base := totals
	first := runtimemetrics.DotnetRuntimeMetricSnapshot{Exceptions: map[string]uint64{"Failure": 2}}
	require.NoError(t, totals.merge(base, &first))
	require.Equal(t, map[string]uint64{"Failure": 12, "Quiet": 4}, first.Exceptions)
	second := runtimemetrics.DotnetRuntimeMetricSnapshot{Exceptions: map[string]uint64{"Failure": 3, "New": 1}}
	require.NoError(t, totals.merge(base, &second))
	require.Equal(t, map[string]uint64{"Failure": 13, "Quiet": 4, "New": 1}, second.Exceptions)
	require.Equal(t, map[string]uint64{"Failure": 12, "Quiet": 4}, first.Exceptions)
	require.Equal(t, map[string]uint64{"Failure": 10, "Quiet": 4}, base.exceptions)

	missing := runtimemetrics.DotnetRuntimeMetricSnapshot{}
	require.NoError(t, totals.merge(base, &missing))
	require.Nil(t, missing.Exceptions)
	require.Equal(t, second.Exceptions, totals.exceptions)

	base = totals
	quiet := runtimemetrics.DotnetRuntimeMetricSnapshot{Exceptions: map[string]uint64{}}
	require.NoError(t, totals.merge(base, &quiet))
	require.Equal(t, second.Exceptions, quiet.Exceptions)
	resumed := runtimemetrics.DotnetRuntimeMetricSnapshot{Exceptions: map[string]uint64{"Failure": 1}}
	require.NoError(t, totals.merge(base, &resumed))
	require.Equal(t, map[string]uint64{"Failure": 14, "Quiet": 4, "New": 1}, resumed.Exceptions)
	require.Equal(t, map[string]uint64{"Failure": 13, "Quiet": 4, "New": 1}, quiet.Exceptions)
	require.Equal(t, quiet.Exceptions, base.exceptions)
}

func TestExceptionSessionTotalsOverflowPreservesState(t *testing.T) {
	totals := cumulativeSessionTotals{exceptions: map[string]uint64{"Failure": math.MaxInt64}}
	base := totals
	snapshot := runtimemetrics.DotnetRuntimeMetricSnapshot{Exceptions: map[string]uint64{"Failure": 1}}
	require.ErrorContains(t, totals.merge(base, &snapshot), "exceeds exporter integer range")
	require.Equal(t, map[string]uint64{"Failure": math.MaxInt64}, totals.exceptions)
	require.Equal(t, map[string]uint64{"Failure": 1}, snapshot.Exceptions)
}

func TestCumulativeSessionTotalsReconnect(t *testing.T) {
	totals := cumulativeSessionTotals{allocated: 12, workItems: 24, contentions: 36, pause: 1.5, jitTime: 3}
	base := totals
	sample := func(count uint64, seconds float64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		allocated, workItems, contentions := count, count*2, count*3
		pause, jitTime := seconds, seconds*2
		ilBytes, methods := uint64(100), uint64(10)
		return &runtimemetrics.DotnetRuntimeMetricSnapshot{
			GCHeapTotalAllocated: &allocated, ThreadPoolWorkItemCount: &workItems, MonitorLockContentions: &contentions,
			GCPauseTime: &pause, JITCompilationTime: &jitTime,
			JITCompiledILSize: &ilBytes, JITCompiledMethods: &methods,
		}
	}
	first := sample(3, 0.25)
	require.NoError(t, totals.merge(base, first))
	require.Equal(t, uint64(15), *first.GCHeapTotalAllocated)
	require.Equal(t, uint64(30), *first.ThreadPoolWorkItemCount)
	require.Equal(t, uint64(45), *first.MonitorLockContentions)
	require.InDelta(t, 1.75, *first.GCPauseTime, 1e-12)
	require.InDelta(t, 3.5, *first.JITCompilationTime, 1e-12)
	require.Equal(t, uint64(100), *first.JITCompiledILSize)
	require.Equal(t, uint64(10), *first.JITCompiledMethods)

	next := sample(5, 0.5)
	require.NoError(t, totals.merge(base, next))
	require.Equal(t, cumulativeSessionTotals{allocated: 17, workItems: 34, contentions: 51, pause: 2, jitTime: 4}, totals)
	require.Equal(t, uint64(17), *next.GCHeapTotalAllocated)
	require.InDelta(t, 2, *next.GCPauseTime, 1e-12)
	require.Equal(t, uint64(15), *first.GCHeapTotalAllocated, "later snapshots must not change earlier values")
	require.InDelta(t, 1.75, *first.GCPauseTime, 1e-12)

	saved := totals
	var missing runtimemetrics.DotnetRuntimeMetricSnapshot
	require.NoError(t, totals.merge(base, &missing))
	require.Equal(t, saved, totals, "missing fields must retain the latest totals")
	require.Equal(t, runtimemetrics.DotnetRuntimeMetricSnapshot{}, missing)

	base = totals
	reconnected := sample(0, 0)
	require.NoError(t, totals.merge(base, reconnected))
	require.Equal(t, saved, totals, "a new session's zero baseline must preserve published totals")
	require.Equal(t, uint64(17), *reconnected.GCHeapTotalAllocated)
	require.InDelta(t, 2, *reconnected.GCPauseTime, 1e-12)
	require.Equal(t, uint64(100), *reconnected.JITCompiledILSize)
	require.Equal(t, uint64(10), *reconnected.JITCompiledMethods)
}

func TestCumulativeSessionTotalsOverflowPreservesState(t *testing.T) {
	for _, tc := range []struct {
		name string
		base cumulativeSessionTotals
	}{
		{"integer", cumulativeSessionTotals{allocated: 10, workItems: math.MaxInt64}},
		{"duration", cumulativeSessionTotals{allocated: 10, jitTime: math.MaxFloat64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			totals := tc.base
			allocated, workItems := uint64(1), uint64(1)
			jitTime := math.MaxFloat64
			snapshot := runtimemetrics.DotnetRuntimeMetricSnapshot{
				GCHeapTotalAllocated: &allocated, ThreadPoolWorkItemCount: &workItems, JITCompilationTime: &jitTime,
			}
			require.Error(t, totals.merge(tc.base, &snapshot))
			require.Equal(t, tc.base, totals)
		})
	}
}
