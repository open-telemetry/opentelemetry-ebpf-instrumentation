// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"errors"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

const processEventsTimeout = 5 * time.Second

type processEventProbes struct {
	validPids *ebpf.Map
	events    *ringbuf.Reader
}

func loadProcessEventProbes(t *testing.T) *processEventProbes {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpf()
	require.NoError(t, err)
	for _, m := range spec.Maps {
		if m.Pinning == ebpfconvenience.PinInternal || m.Pinning == ebpf.PinByName {
			m.Pinning = ebpf.PinNone
		}
	}
	constants := map[string]any{"filter_pids": int32(1)}
	maps.Copy(constants, ebpfcommon.PIDFilterConstants())
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, constants))

	var objs struct {
		Fork      *ebpf.Program `ebpf:"obi_kprobe_wake_up_new_task"`
		Exec      *ebpf.Program `ebpf:"obi_kprobe_setup_new_exec"`
		ValidPids *ebpf.Map     `ebpf:"valid_pids"`
		Events    *ebpf.Map     `ebpf:"events"`
	}
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() {
		objs.Fork.Close()
		objs.Exec.Close()
		objs.ValidPids.Close()
		objs.Events.Close()
	})

	for symbol, prog := range map[string]*ebpf.Program{"wake_up_new_task": objs.Fork, "setup_new_exec": objs.Exec} {
		kp, err := link.Kprobe(symbol, prog, nil)
		require.NoError(t, err)
		t.Cleanup(func() { kp.Close() })
	}

	events, err := ringbuf.NewReader(objs.Events)
	require.NoError(t, err)
	t.Cleanup(func() { events.Close() })

	return &processEventProbes{validPids: objs.ValidPids, events: events}
}

func (p *processEventProbes) selectTestProcess(t *testing.T) {
	t.Helper()
	pid := uint32(os.Getpid())
	require.NoError(t, p.validPids.Put(pid/64, uint64(1)<<(pid%64)))
}

func (p *processEventProbes) readUntil(t *testing.T, done func(*ebpfcommon.ProcessEvent) bool) []ebpfcommon.ProcessEvent {
	t.Helper()
	p.events.SetDeadline(time.Now().Add(processEventsTimeout))

	var events []ebpfcommon.ProcessEvent
	for {
		record, err := p.events.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			require.Fail(t, "timed out waiting for process events", "got %+v", events)
		}
		require.NoError(t, err)

		eventType := record.RawSample[0]
		if eventType != ebpfcommon.EventTypeProcessFork && eventType != ebpfcommon.EventTypeProcessExec {
			continue
		}
		event, err := ebpfcommon.ReinterpretCast[ebpfcommon.ProcessEvent](record.RawSample)
		require.NoError(t, err)
		events = append(events, *event)
		if done(event) {
			return events
		}
	}
}

func runTrue(t *testing.T) uint32 {
	t.Helper()
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())
	return uint32(cmd.Process.Pid)
}

func pidNamespace(t *testing.T) uint32 {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/ns/pid_for_children", &st))
	return uint32(st.Ino)
}

func eventOf(events []ebpfcommon.ProcessEvent, eventType uint8, pid uint32) (ebpfcommon.ProcessEvent, bool) {
	i := slices.IndexFunc(events, func(e ebpfcommon.ProcessEvent) bool {
		return e.Type == eventType && e.Pid.UserPid == pid
	})
	if i < 0 {
		return ebpfcommon.ProcessEvent{}, false
	}
	return events[i], true
}

func TestForkAndExecReportTheChild(t *testing.T) {
	probes := loadProcessEventProbes(t)
	probes.selectTestProcess(t)

	child := runTrue(t)
	events := probes.readUntil(t, func(e *ebpfcommon.ProcessEvent) bool {
		return e.Type == ebpfcommon.EventTypeProcessExec && e.Pid.UserPid == child
	})

	fork, ok := eventOf(events, ebpfcommon.EventTypeProcessFork, child)
	require.True(t, ok, "the fork of the child must be reported before its exec")
	ns := pidNamespace(t)
	assert.Equal(t, ns, fork.Pid.Ns)
	assert.Equal(t, uint32(os.Getpid()), fork.Parent.UserPid)
	assert.Equal(t, ns, fork.Parent.Ns)

	execEvent, _ := eventOf(events, ebpfcommon.EventTypeProcessExec, child)
	assert.Equal(t, ns, execEvent.Pid.Ns)
	assert.Greater(t, execEvent.Ts, fork.Ts)
}

func TestForkOutsideThePIDFilterIsNotReported(t *testing.T) {
	probes := loadProcessEventProbes(t)

	unselected := runTrue(t)
	probes.selectTestProcess(t)
	selected := runTrue(t)

	// the ring buffer keeps order: this fork follows anything the first child sent
	events := probes.readUntil(t, func(e *ebpfcommon.ProcessEvent) bool {
		return e.Type == ebpfcommon.EventTypeProcessFork && e.Pid.UserPid == selected
	})
	_, reported := eventOf(events, ebpfcommon.EventTypeProcessFork, unselected)
	assert.False(t, reported)
	_, reported = eventOf(events, ebpfcommon.EventTypeProcessExec, unselected)
	assert.False(t, reported)
}

func TestNewThreadsAreNotReportedAsForks(t *testing.T) {
	probes := loadProcessEventProbes(t)
	probes.selectTestProcess(t)

	tids := newThreads(t)
	sentinel := runTrue(t)

	events := probes.readUntil(t, func(e *ebpfcommon.ProcessEvent) bool {
		return e.Type == ebpfcommon.EventTypeProcessFork && e.Pid.UserPid == sentinel
	})
	_, reported := eventOf(events, ebpfcommon.EventTypeProcessFork, uint32(os.Getpid()))
	assert.False(t, reported, "threads %v of this process must not be reported as forked processes", tids)
}

// parks goroutines on locked OS threads until the runtime clones a new one
func newThreads(t *testing.T) []int {
	t.Helper()
	before := processThreads(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	tids := make(chan int)
	var created []int
	for range 64 {
		go func() {
			runtime.LockOSThread()
			tids <- unix.Gettid()
			<-release
		}()
		if tid := <-tids; !slices.Contains(before, tid) {
			created = append(created, tid)
		}
		if len(created) > 0 {
			return created
		}
	}
	require.Fail(t, "the runtime cloned no new thread")
	return nil
}

func processThreads(t *testing.T) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/task")
	require.NoError(t, err)

	tids := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		require.NoError(t, err)
		tids = append(tids, tid)
	}
	return tids
}
