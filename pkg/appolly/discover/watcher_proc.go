// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/watcher"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

const (
	emptyDuration = time.Duration(0)
	// procStatBufSize safely fits /proc/<pid>/stat for our parsing path.
	procStatBufSize = 4096
)

// procStatBufPool amortizes stat buffer allocations across all procStatReader callers.
var procStatBufPool = sync.Pool{
	New: func() any {
		return new([procStatBufSize]byte)
	},
}

type WatchEventType int

const (
	EventCreated = WatchEventType(iota)
	EventDeleted
	EventInstanceDeleted
)

type Event[T any] struct {
	Type WatchEventType
	Obj  T
}

type ProcessAttrs struct {
	pid            app.PID
	openPorts      []uint32
	metadata       map[string]string
	podLabels      map[string]string
	podAnnotations map[string]string
	processAge     time.Duration
	detectedType   svc.InstrumentableType
	cmdArgs        string
}

func wplog() *slog.Logger {
	return slog.With("component", "discover.ProcessWatcher")
}

// ProcessWatcherFunc polls every PollInterval for new processes and forwards either new or deleted process PIDs
// as well as PIDs from processes that setup a new connection.
// When addedPIDsNotify is non-nil, the watcher receives PIDs that were added to the dynamic selector and
// forgets them from its tracked state so they are re-emitted as new on the next poll (supporting adding
// an already-seen process).
func ProcessWatcherFunc(cfg *obi.Config, ebpfContext *ebpfcommon.EBPFEventContext, output *msg.Queue[[]Event[ProcessAttrs]], findingCriteria []services.Selector, addedPIDsNotify <-chan []app.PID) swarm.RunFunc {
	acc := pollAccounter{
		cfg:             cfg,
		output:          output,
		pids:            map[app.PID]*ProcessAttrs{},
		listProcesses:   fetchProcessPorts,
		executableReady: ExecutableReady,
		loadBPFWatcher:  loadBPFWatcher,
		loadBPFLogger:   loadBPFLogger,
		stateMux:        sync.Mutex{},
		findingCriteria: findingCriteria,
		ebpfContext:     ebpfContext,
		addedPIDsNotify: addedPIDsNotify,
	}
	return acc.run
}

// TODO: don't report twice the same process (unless a new port is created)
// TODO: keep listprocesses but run it only once
// TODO: maybe an "process cleaner"
// TODO: use executableready

// TODO: combine the poller with an eBPF listener (poll at start and e.g. every 30 seconds, and keep listening eBPF in background)
// ^ This is partially done, although it's not fully async, we only use the info to reduce the overhead of port scanning.
type pollAccounter struct {
	cfg *obi.Config
	// last polled process:ports accessible by its pid
	pids map[app.PID]*ProcessAttrs

	// injectable function
	listProcesses func() (map[app.PID]ProcessAttrs, error)
	// injectable function
	executableReady func(app.PID) (string, bool)
	// injectable function to load the bpf program
	loadBPFWatcher func(ctx context.Context, ebpfContext *ebpfcommon.EBPFEventContext, cfg *obi.Config, events chan<- watcher.Event) error
	loadBPFLogger  func(ctx context.Context, ebpfContext *ebpfcommon.EBPFEventContext, cfg *obi.Config) error
	// we use these to ensure we poll for the open ports effectively
	stateMux        sync.Mutex
	findingCriteria []services.Selector
	output          *msg.Queue[[]Event[ProcessAttrs]]
	ebpfContext     *ebpfcommon.EBPFEventContext
	// when non-nil, PIDs received here are removed from pids/pidPorts so they are re-emitted as new on next poll
	addedPIDsNotify <-chan []app.PID
	// pidsMu protects pids and pidPorts so the addedPIDsNotify goroutine can call forgetPIDs while snapshot runs
	pidsMu sync.Mutex
}

func (pa *pollAccounter) run(ctx context.Context) {
	defer pa.output.Close()

	log := slog.With("component", "discover.ProcessWatcher")

	bpfWatchEvents := make(chan watcher.Event, 100)
	if err := pa.loadBPFWatcher(ctx, pa.ebpfContext, pa.cfg, bpfWatchEvents); err != nil {
		log.Error("Unable to load eBPF watcher for process events", "error", err)
		// will stop pipeline in cascade
		return
	}

	if pa.cfg.EBPF.BpfDebug {
		if err := pa.loadBPFLogger(ctx, pa.ebpfContext, pa.cfg); err != nil {
			log.Error("Unable to load eBPF logger for process events", "error", err)
			// keep running without logs
		}
	}

	// after we are already subscribed to bpf watcher events, let's
	// populate a first snapshot of the pre-existing processes
	procs, err := pa.listProcesses()
	if err != nil {
		log.Error("can't get system processes", "error", err)
	} else {
		var events []Event[ProcessAttrs]
		for _, proc := range procs {
			events = append(events, Event[ProcessAttrs]{
				Type: EventCreated,
				Obj:  proc,
			})
		}
		pa.output.SendCtx(ctx, events)
	}

	if pa.addedPIDsNotify != nil {
		go pa.runAddedPIDsNotify(ctx, log)
	}

	pa.watchForProcessEvents(ctx, log, bpfWatchEvents)
}

// runAddedPIDsNotify runs in a goroutine; it receives PIDs added to the dynamic selector
// and calls forgetPIDs so they are re-emitted as new on the next poll.
func (pa *pollAccounter) runAddedPIDsNotify(ctx context.Context, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case pids, ok := <-pa.addedPIDsNotify:
			if !ok {
				return
			}
			pa.forgetPIDs(pids)
			log.Debug("forgot PIDs so they can be re-emitted as new", "pids", pids)
		}
	}
}

// forgetPIDs removes the given PIDs from the watcher's tracked state so they will be
// reported as new on the next poll (e.g. when added to the dynamic PID selector).
func (pa *pollAccounter) forgetPIDs(pids []app.PID) {
	pa.pidsMu.Lock()
	defer pa.pidsMu.Unlock()
	for _, pid := range pids {
		delete(pa.pids, pid)
	}
	for pp := range pa.pids {
		for _, pid := range pids {
			if pp == pid {
				delete(pa.pids, pp)
				break
			}
		}
	}
}

func portOfInterest(criteria []services.Selector, port int) bool {
	for _, cr := range criteria {
		if cr.GetOpenPorts().Matches(port) {
			return true
		}
	}
	return false
}

func (pa *pollAccounter) watchForProcessEvents(
	ctx context.Context,
	log *slog.Logger,
	events <-chan watcher.Event,
) {
	swarms.ForEachInput(ctx, events, log.Debug, func(e watcher.Event) {
		switch e.Type {
		case watcher.Ready:
			// TODO: decide what to do
		case watcher.NewPort:
			if pa.cfg.Port.Matches(int(e.Port)) || portOfInterest(pa.findingCriteria, int(e.Port)) {
				attrs := pa.attrsFor(app.PID(e.Pid))
				attrs.openPorts = append(attrs.openPorts, uint32(e.Port))
				pa.output.SendCtx(ctx, []Event[ProcessAttrs]{{Type: EventCreated, Obj: *attrs}})
			}
		case watcher.NewProcess:
			attrs := pa.attrsFor(app.PID(e.Pid))
			pa.output.SendCtx(ctx, []Event[ProcessAttrs]{{Type: EventCreated, Obj: *attrs}})
		default:
			log.Warn("Unknown ebpf process watch event", "type", e.Type)
		}
	})
}

func (pa *pollAccounter) attrsFor(pid app.PID) *ProcessAttrs {
	pa.pidsMu.Lock()
	defer pa.pidsMu.Unlock()
	attrs, ok := pa.pids[pid]
	if !ok {
		attrs = &ProcessAttrs{
			pid:          pid,
			detectedType: svc.InstrumentableUnknown,
			processAge:   processAgeFunc(pid),
		}
		pa.pids[pid] = attrs
	}
	return attrs
}

func ExecutableReady(pid app.PID) (string, bool) {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return "", false
	}
	exePath, err := proc.Exe()
	if err != nil {
		return exePath, errors.Is(err, os.ErrNotExist)
	}

	return exePath, (exePath != "/" && exePath != "")
}

func ProcessAgeFunc() func(app.PID) time.Duration {
	r := procStatReader{}
	return r.processAge
}

// overridden in tests
var processAgeFunc = ProcessAgeFunc()

// see https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
func parseProcStatField(buf string, field int) string {
	inParens := false

	// field 2 is the comm, which is deliminated by parens and can contain
	// whitespace, e.g. (foo bar) - this function accounts for that
	f := func(c rune) bool {
		if c == '(' {
			inParens = true
			return true
		}

		if inParens {
			if c == ')' {
				inParens = false
				return true
			}

			return false
		}

		return c == ' '
	}

	i := 1

	for word := range strings.FieldsFuncSeq(buf, f) {
		if i == field {
			return word
		}

		i++
	}

	return ""
}

type procStatReader struct{}

func (r *procStatReader) getProcStatField(pid app.PID, field int) string {
	bufPtr, ok := procStatBufPool.Get().(*[procStatBufSize]byte)
	if !ok {
		bufPtr = new([procStatBufSize]byte)
	}
	defer procStatBufPool.Put(bufPtr)

	path := fmt.Sprintf("/proc/%d/stat", pid)

	f, err := os.Open(path)
	if err != nil {
		return ""
	}

	defer f.Close()

	nbytes, err := f.Read(bufPtr[:])
	if err != nil {
		return ""
	}

	return parseProcStatField(string(bufPtr[:nbytes]), field)
}

func ticksToNanosecond(ticks uint64) uint64 {
	clkTck := 100 // default for Linux

	return ticks * 1e9 / uint64(clkTck)
}

func nsToDuration(ns uint64) time.Duration {
	if ns > math.MaxInt64 {
		return time.Duration(math.MaxInt64) // clamp
	}

	return time.Duration(ns)
}

func (r *procStatReader) getProcStartTime(pid app.PID) uint64 {
	const startTimePos = 22

	val := r.getProcStatField(pid, startTimePos)

	if val == "" {
		return 0
	}

	startTimeTicks, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0
	}

	return ticksToNanosecond(startTimeTicks)
}

func (r *procStatReader) processAge(pid app.PID) time.Duration {
	procStartTime := r.getProcStartTime(pid)

	if procStartTime == 0 {
		return emptyDuration
	}

	now := currentTime()

	if now < procStartTime {
		return emptyDuration
	}

	return nsToDuration(now - procStartTime)
}

// overridden in tests
var processPidsFunc = process.Pids

// fetchProcessConnections returns a map with the PIDs of all the running processes as a key,
// and the open ports for the given process as a value.
// This runs only once during OBI startup, to get a view of the pre-existing processes that
// might be instrumented, before moving to an eBPF-based notification (after each connection binding)
func fetchProcessPorts() (map[app.PID]ProcessAttrs, error) {
	log := wplog()
	pids, err := processPidsFunc()
	if err != nil {
		return nil, fmt.Errorf("can't get processes: %w", err)
	}
	processes := make(map[app.PID]ProcessAttrs, len(pids))
	for _, pid := range pids {
		conns, err := net.ConnectionsPid("inet", pid)
		if err != nil {
			log.Debug("can't get connections for process. Skipping", "pid", pid, "error", err)
			continue
		}
		var openPorts []uint32
		for _, conn := range conns {
			openPorts = append(openPorts, conn.Laddr.Port)
		}
		processes[app.PID(pid)] = ProcessAttrs{pid: app.PID(pid), detectedType: svc.InstrumentableUnknown, openPorts: openPorts}
	}
	return processes, nil
}

func loadBPFWatcher(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, cfg *obi.Config, events chan<- watcher.Event) error {
	wt := watcher.New(cfg, events)
	return ebpf.RunUtilityTracer(ctx, ebpfEventContext, wt, cfg)
}

func loadBPFLogger(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, cfg *obi.Config) error {
	wt := logger.New(cfg)
	return ebpf.RunUtilityTracer(ctx, ebpfEventContext, wt, cfg)
}
