// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// fakeOTelTracesPIDFilter records the marks written to it; its first failures writes fail
type fakeOTelTracesPIDFilter struct {
	marks    map[app.PID]bool
	calls    int
	failures int
}

func newFakeOTelTracesPIDFilter() *fakeOTelTracesPIDFilter {
	return &fakeOTelTracesPIDFilter{marks: map[app.PID]bool{}}
}

func (f *fakeOTelTracesPIDFilter) Marked(pid app.PID) bool {
	return f.marks[pid]
}

func (f *fakeOTelTracesPIDFilter) Mark(pid app.PID, exportsTraces bool) error {
	f.calls++
	if f.failures > 0 {
		f.failures--
		return errors.New("map update failed")
	}
	f.marks[pid] = exportsTraces
	return nil
}

func traceExport(pid app.PID, end time.Duration) request.Span {
	return request.Span{
		Type: request.EventTypeHTTPClient, Path: "/v1/traces", Status: 200, End: int64(end),
		Pid: request.PidInfo{UserPID: pid, Namespace: 42},
	}
}

func TestOTelTracesPIDFilter(t *testing.T) {
	original := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid, pid / 1000}, nil
	}
	t.Cleanup(func() { readNamespacePIDs = original })

	for _, tc := range []struct {
		name    string
		exclude bool
		path    string
		status  int
		marked  bool
	}{
		{name: "trace export", exclude: true, path: "/v1/traces", status: 200, marked: true},
		{name: "metric export", exclude: true, path: "/v1/metrics", status: 200},
		{name: "failed trace export", exclude: true, path: "/v1/traces", status: 500},
		{name: "exclusion disabled", path: "/v1/traces", status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pf := NewPIDsFilter(&services.DiscoveryConfig{
				ExcludeOTelInstrumentedServices: tc.exclude,
			}, slog.Default(), nil)
			pf.AllowPID(1000, 42, exec.New(exec.Init{}), PIDTypeKProbes)
			pf.AllowPID(2000, 42, exec.New(exec.Init{}), PIDTypeGo)
			filter := newFakeOTelTracesPIDFilter()
			pf.SetOTelTracesPIDFilter(filter)

			pf.Filter([]request.Span{{
				Type: request.EventTypeHTTPClient, Path: tc.path, Status: tc.status,
				Pid: request.PidInfo{UserPID: 1, HostPID: 9000, Namespace: 42},
			}})
			assert.Equal(t, map[app.PID]bool{1000: tc.marked, 2000: false}, filter.marks)
			pf.BlockPID(1000, 42)
			assert.False(t, filter.marks[1000])
		})
	}
}

func TestOTelTracesPIDFilterRetriesAndFollowsPIDLifecycle(t *testing.T) {
	original := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) { return []app.PID{pid}, nil }
	t.Cleanup(func() { readNamespacePIDs = original })

	pf := NewPIDsFilter(&services.DiscoveryConfig{
		ExcludeOTelInstrumentedServices: true,
	}, slog.Default(), nil)
	pf.AllowPID(1000, 42, exec.New(exec.Init{}), PIDTypeGo)
	span := traceExport(1000, 0)
	pf.Filter([]request.Span{span})

	filter := newFakeOTelTracesPIDFilter()
	filter.failures = 1
	pf.SetOTelTracesPIDFilter(filter)
	assert.False(t, filter.marks[1000])
	pf.Filter([]request.Span{span})
	assert.True(t, filter.marks[1000], "an already detected service must retry failed map updates")

	pf.BlockPID(1000, 42)
	assert.False(t, filter.marks[1000])
	pf.Filter([]request.Span{span})
	assert.False(t, filter.marks[1000], "late spans must not mark removed PIDs")

	pf.AllowPID(1000, 42, exec.New(exec.Init{}), PIDTypeGo)
	pf.Filter([]request.Span{span})
	assert.False(t, filter.marks[1000], "late spans must not mark a reused PID")
	span.End = int64(pidsFilterMonoNow() + time.Second)
	pf.Filter([]request.Span{span})
	assert.True(t, filter.marks[1000])

	pf.RemoveOTelTracesPIDFilter()
	beforeDetach := filter.calls
	pf.BlockPID(1000, 42)
	require.Equal(t, beforeDetach, filter.calls, "detaching must stop updates before the BPF map closes")
}

func TestOTelTracesPIDFilterMarksSharedClassification(t *testing.T) {
	original := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) { return []app.PID{pid}, nil }
	t.Cleanup(func() { readNamespacePIDs = original })

	pf := NewPIDsFilter(&services.DiscoveryConfig{
		ExcludeOTelInstrumentedServices: true,
	}, slog.Default(), nil)
	// workers sharing one classification, like Python's
	workers := exec.New(exec.Init{})
	pf.AllowPID(1000, 42, workers, PIDTypeKProbes)
	pf.AllowPID(2000, 42, workers, PIDTypeKProbes)
	pf.AllowPID(3000, 42, workers, PIDTypeKProbes)
	pf.BlockPID(3000, 42)
	pf.AllowPID(4000, 42, exec.New(exec.Init{}), PIDTypeKProbes)
	filter := newFakeOTelTracesPIDFilter()
	pf.SetOTelTracesPIDFilter(filter)

	pf.Filter([]request.Span{traceExport(1000, 0)})
	// a removed worker is never written
	assert.Equal(t, map[app.PID]bool{1000: true, 2000: true, 4000: false}, filter.marks,
		"one worker's export marks every live worker, and no other process")

	calls := filter.calls
	pf.Filter([]request.Span{traceExport(1000, 0), traceExport(2000, 0)})
	assert.Equal(t, calls, filter.calls, "exports of marked processes skip the scan")

	pf.AllowPID(5000, 42, workers, PIDTypeKProbes)
	assert.True(t, filter.marks[5000], "a worker added later is marked as it is added")
}

func TestOTelTracesPIDFilterForkedChildMarksItsParent(t *testing.T) {
	original := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) { return []app.PID{pid}, nil }
	t.Cleanup(func() { readNamespacePIDs = original })

	pf := NewPIDsFilter(&services.DiscoveryConfig{
		ExcludeOTelInstrumentedServices: true,
	}, slog.Default(), nil)
	pf.AllowPID(1000, 42, exec.New(exec.Init{}), PIDTypeKProbes)
	filter := newFakeOTelTracesPIDFilter()
	pf.SetOTelTracesPIDFilter(filter)

	forkedAt := pidsFilterMonoNow()
	pf.AllowForkedChild(request.PidInfo{UserPID: 1001, Namespace: 42}, request.PidInfo{UserPID: 1000, Namespace: 42}, forkedAt)
	export := traceExport(1001, forkedAt+time.Millisecond)

	pf.Filter([]request.Span{export})
	// the child has no pid OBI's /proc numbers it with until discovery registers it
	assert.Equal(t, map[app.PID]bool{1000: true}, filter.marks,
		"the export of an unregistered child marks the parent whose classification it shares")

	calls := filter.calls
	pf.Filter([]request.Span{export})
	assert.Equal(t, calls, filter.calls, "later exports of the unregistered child skip the scan")
}
