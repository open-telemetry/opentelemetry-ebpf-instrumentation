// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"log/slog"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

const (
	forkNS     = 33
	parentPID  = app.PID(100)
	childPID   = app.PID(200)
	forkedTime = time.Hour
)

var (
	parentInfo = request.PidInfo{HostPID: 1100, UserPID: parentPID, Namespace: forkNS}
	childInfo  = request.PidInfo{HostPID: 1200, UserPID: childPID, Namespace: forkNS}
)

func forkedFilter(t *testing.T, now *time.Duration) *PIDsFilter {
	t.Helper()
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	*now = forkedTime
	pidsFilterMonoNow = func() time.Duration { return *now }
	t.Cleanup(func() { pidsFilterMonoNow = timing.MonoTimeNow })

	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	pf.AllowPID(parentPID, forkNS, serviceNamed("worker"), PIDTypeKProbes)
	return pf
}

func childSpan(end time.Duration) request.Span {
	return request.Span{Pid: childInfo, End: int64(end)}
}

func TestForkedChildSpansFiledUnderParent(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	require.Empty(t, pf.Filter([]request.Span{childSpan(forkedTime + time.Millisecond)}),
		"a child discovery hasn't seen is dropped until its fork is known")

	pf.AllowForkedChild(childInfo, parentInfo, forkedTime)

	assert.True(t, pf.ValidPID(childPID, forkNS, PIDTypeKProbes))
	spans := pf.Filter([]request.Span{childSpan(forkedTime + time.Millisecond)})
	require.Len(t, spans, 1)
	assert.Equal(t, "worker", spans[0].Service.UID.Name)

	_, listed := pf.CurrentPIDs(PIDTypeKProbes)[forkNS][childPID]
	assert.False(t, listed, "a forked child is admitted for its spans, not listed as a process of its own")
	assert.NotContains(t, pf.ProcPIDs(PIDTypeKProbes), childPID, "a forked child must not enter the BPF pid filter")
}

func TestForkedChildOfUnknownParentIgnored(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	stranger := request.PidInfo{UserPID: 999, Namespace: forkNS}
	pf.AllowForkedChild(childInfo, stranger, forkedTime)

	assert.False(t, pf.ValidPID(childPID, forkNS, PIDTypeKProbes))
	assert.Empty(t, pf.Filter([]request.Span{childSpan(forkedTime + time.Millisecond)}))
}

func TestForkedGrandchildIgnored(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	pf.AllowForkedChild(childInfo, parentInfo, forkedTime)
	grandchild := request.PidInfo{UserPID: 300, Namespace: forkNS}
	pf.AllowForkedChild(grandchild, childInfo, forkedTime)

	assert.False(t, pf.ValidPID(300, forkNS, PIDTypeKProbes))
}

func TestForkedChildEndsAtExec(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	pf.AllowForkedChild(childInfo, parentInfo, forkedTime)
	execTime := forkedTime + time.Second
	pf.EndForkedChild(childInfo, execTime)
	now = execTime + time.Second

	spans := pf.Filter([]request.Span{childSpan(execTime - time.Millisecond)})
	require.Len(t, spans, 1, "spans from before exec still belong to the parent's program")
	assert.Equal(t, "worker", spans[0].Service.UID.Name)
	assert.Empty(t, pf.Filter([]request.Span{childSpan(execTime + time.Millisecond)}),
		"after exec the child runs another program, which only discovery may attribute")
}

func TestDiscoveryTakesOverForkedChild(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	pf.AllowForkedChild(childInfo, parentInfo, forkedTime)
	now += time.Second
	pf.AllowPID(childPID, forkNS, serviceNamed("child"), PIDTypeKProbes)

	spans := pf.Filter([]request.Span{childSpan(now + time.Millisecond)})
	require.Len(t, spans, 1)
	assert.Equal(t, "child", spans[0].Service.UID.Name)
	_, listed := pf.CurrentPIDs(PIDTypeKProbes)[forkNS][childPID]
	assert.True(t, listed, "once discovery registers the child it is a process of its own")

	pf.BlockPID(childPID, forkNS)
	assert.Empty(t, pf.Filter([]request.Span{childSpan(now + time.Second)}),
		"the fork event doesn't outlive discovery's removal")
}

func TestForkedChildExpires(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	pf.AllowForkedChild(childInfo, parentInfo, forkedTime)

	require.Len(t, pf.Filter([]request.Span{childSpan(forkedTime + pidRemovalRetention)}), 1)
	assert.Empty(t, pf.Filter([]request.Span{childSpan(forkedTime + pidRemovalRetention + time.Millisecond)}),
		"a child discovery never registered is not filed under its parent forever")
}

func TestForkedChildrenAreBounded(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	for pid := range app.PID(forkedChildrenCapacity + 1) {
		pf.AllowForkedChild(request.PidInfo{UserPID: childPID + pid, Namespace: forkNS}, parentInfo, forkedTime)
	}

	assert.False(t, pf.ValidPID(childPID, forkNS, PIDTypeKProbes), "the oldest child makes room")
	assert.True(t, pf.ValidPID(childPID+1, forkNS, PIDTypeKProbes))
	assert.True(t, pf.ValidPID(childPID+forkedChildrenCapacity, forkNS, PIDTypeKProbes))
}

func TestForkedChildOfParentRemovedBeforeTheForkIsRead(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	forkTime := now
	now += time.Second
	pf.BlockPID(parentPID, forkNS)
	pf.AllowForkedChild(childInfo, parentInfo, forkTime)

	spans := pf.Filter([]request.Span{childSpan(forkTime + time.Millisecond)})
	require.Len(t, spans, 1)
	assert.Equal(t, "worker", spans[0].Service.UID.Name)

	sibling := request.PidInfo{UserPID: 201, Namespace: forkNS}
	pf.AllowForkedChild(sibling, parentInfo, now+time.Second)
	assert.False(t, pf.ValidPID(sibling.UserPID, forkNS, PIDTypeKProbes), "a fork after the removal isn't the parent's")
}

func TestForkedChildOfReusedParentPID(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	oldFork := now
	now += time.Second
	pf.BlockPID(parentPID, forkNS)
	now += time.Second
	pf.AllowPID(parentPID, forkNS, serviceNamed("other"), PIDTypeKProbes)
	newFork := now + time.Second
	sibling := request.PidInfo{UserPID: 201, Namespace: forkNS}

	pf.AllowForkedChild(childInfo, parentInfo, oldFork)
	pf.AllowForkedChild(sibling, parentInfo, newFork)

	spans := pf.Filter([]request.Span{
		childSpan(oldFork + time.Millisecond),
		{Pid: sibling, End: int64(newFork + time.Millisecond)},
	})
	require.Len(t, spans, 2)
	assert.Equal(t, "worker", spans[0].Service.UID.Name, "the process that forked it, not the pid's next owner")
	assert.Equal(t, "other", spans[1].Service.UID.Name)
}

func TestForkedChildKeepsLiveDiscoveredPID(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	pf.AllowPID(childPID, forkNS, serviceNamed("other"), PIDTypeKProbes)
	pf.AllowForkedChild(childInfo, parentInfo, forkedTime)

	spans := pf.Filter([]request.Span{childSpan(forkedTime + time.Millisecond)})
	require.Len(t, spans, 1)
	assert.Equal(t, "other", spans[0].Service.UID.Name, "a fork event doesn't override discovery")
}

func TestForkedChildReusingRemovedPID(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)

	pf.AllowPID(childPID, forkNS, serviceNamed("old"), PIDTypeKProbes)
	beforeExit := now - time.Second
	pf.BlockPID(childPID, forkNS)
	now += time.Second
	pf.AllowForkedChild(childInfo, parentInfo, now)

	spans := pf.Filter([]request.Span{childSpan(beforeExit), childSpan(now + time.Millisecond)})
	require.Len(t, spans, 2)
	assert.Equal(t, "old", spans[0].Service.UID.Name)
	assert.Equal(t, "worker", spans[1].Service.UID.Name)
}

func processEventRecord(eventType uint8, pid, parent request.PidInfo, at time.Duration) *ringbuf.Record {
	event := ProcessEvent{Type: eventType, Ts: uint64(at)}
	event.Pid.HostPid, event.Pid.UserPid, event.Pid.Ns = uint32(pid.HostPID), uint32(pid.UserPID), pid.Namespace
	event.Parent.HostPid, event.Parent.UserPid, event.Parent.Ns = uint32(parent.HostPID), uint32(parent.UserPID), parent.Namespace
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
	return &ringbuf.Record{RawSample: append([]byte(nil), raw...)}
}

func TestProcessEventHandlers(t *testing.T) {
	var now time.Duration
	pf := forkedFilter(t, &now)
	eventCtx := NewEBPFEventContext()
	RegisterProcessEventHandlers(eventCtx, pf)

	handled, err := eventCtx.HandleInternalEvent(
		processEventRecord(EventTypeProcessFork, childInfo, parentInfo, forkedTime))
	require.NoError(t, err)
	require.True(t, handled)
	require.True(t, pf.ValidPID(childPID, forkNS, PIDTypeKProbes))

	execTime := forkedTime + time.Second
	handled, err = eventCtx.HandleInternalEvent(
		processEventRecord(EventTypeProcessExec, childInfo, request.PidInfo{}, execTime))
	require.NoError(t, err)
	require.True(t, handled)
	assert.Empty(t, pf.Filter([]request.Span{childSpan(execTime + time.Millisecond)}))
}
