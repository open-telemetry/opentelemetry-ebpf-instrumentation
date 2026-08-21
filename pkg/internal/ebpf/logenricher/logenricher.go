// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher // import "go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/shardedqueue"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_event_t -target amd64,arm64 Bpf ../../../../bpf/logenricher/logenricher.c -- -I../../../../bpf -I../../../../bpf

type LogEvent struct {
	orig    BpfLogEventT
	logLine string
	dest    string
}

type Tracer struct {
	ctx         context.Context
	cfg         *obi.Config
	bpfObjects  BpfObjects
	closers     []io.Closer
	log         *slog.Logger
	fdCache     *expirable.LRU[string, *os.File]
	asyncWriter *shardedqueue.ShardedQueue[LogEvent]
	formatter   logFormatter
	pids        map[uint64][]uint64         // pid:[]nsPids
	pidServices map[uint32]*exec.FileInfo   // host pid -> file info, for run-time OTel-export check in handle()
	trackedPids map[uint32]struct{}         // host pids currently allowed
	logPipes    map[uint64]map[uint32][]int // log pipe inode -> host pid -> fds (1 and/or 2)
	pidPipes    map[uint32]map[int]uint64   // host pid -> fd -> registered log pipe inode
	pidsMU      sync.Mutex
}

func New(cfg *obi.Config) *Tracer {
	logger := slog.With("component", "logenricher")

	if !ebpfcommon.SupportsLogInjection(logger) {
		logger.Warn("log enrichment not supported on this system!")
		return nil
	}

	tr := &Tracer{
		log: logger,
		cfg: cfg,
		fdCache: expirable.NewLRU[string, *os.File](cfg.EBPF.LogEnricher.CacheSize, func(_ string, f *os.File) {
			f.Close()
		}, cfg.EBPF.LogEnricher.CacheTTL),
		formatter:   newLogFormatter(cfg.EBPF.LogEnricher),
		pids:        make(map[uint64][]uint64),
		pidServices: make(map[uint32]*exec.FileInfo),
		trackedPids: make(map[uint32]struct{}),
		logPipes:    make(map[uint64]map[uint32][]int),
		pidPipes:    make(map[uint32]map[int]uint64),
	}

	asyncWriter := shardedqueue.NewShardedQueue[LogEvent](
		cfg.EBPF.LogEnricher.AsyncWriterWorkers,
		cfg.EBPF.LogEnricher.AsyncWriterChannelLen,
		func(e LogEvent) string { return e.dest },
		func(_ int, ch <-chan LogEvent) {
			for e := range ch {
				tr.handle(e)
			}
		},
	)

	tr.asyncWriter = asyncWriter

	return tr
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Tracer) constants() map[string]any {
	return map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug}
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	m := map[string]ebpfcommon.ProbeDesc{
		"tty_write": {
			Start:    p.bpfObjects.ObiKprobeTtyWrite,
			Required: true,
		},
		"ksys_write": {
			Start:    p.bpfObjects.ObiKprobeKsysWrite,
			Required: true,
		},
	}

	hasDoWritev, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymDoWritev)
	if err != nil {
		p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymDoWritev, "error", err)
	}

	if hasDoWritev {
		m["do_writev"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiKprobeDoWritev,
			Required: false,
		}
	} else {
		p.log.Warn("do_writev kernel symbol not available; writev()-based log writes won't be enriched")
	}

	hasPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymPipeWrite)
	if err != nil {
		p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymPipeWrite, "error", err)
	}

	if hasPipeWrite {
		m["pipe_write"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiKprobePipeWrite,
			Required: true,
		}
	} else {
		hasAnonPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymAnonPipeWrite)
		if err != nil {
			p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymAnonPipeWrite, "error", err)
		}

		if hasAnonPipeWrite {
			m["anon_pipe_write"] = ebpfcommon.ProbeDesc{
				Start:    p.bpfObjects.ObiKprobePipeWrite,
				Required: true,
			}
		} else {
			p.log.Error("neither anon_pipe_write nor pipe_write kernel symbols are available; log enrichment may not work correctly")
		}
	}

	return m
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return nil
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
}

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	return nil
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) pidKey(nsid, pid uint32) uint64 {
	return (uint64(nsid) << 32) | uint64(pid)
}

func (p *Tracer) shouldOmitSpanID(hostPID uint32) bool {
	if !p.cfg.Discovery.ExcludeOTelInstrumentedServices {
		return false
	}

	p.pidsMU.Lock()
	s := p.pidServices[hostPID]
	p.pidsMU.Unlock()

	return s != nil && s.ExportsOTelTraces()
}

func (p *Tracer) addPID(key uint64) error {
	p.log.Debug("adding pid", "pid", uint32(key), "ns", key>>32)
	if p.bpfObjects.LogEnricherPids == nil {
		return fmt.Errorf("BPF objects not loaded, cannot add pid %d (ns=%d)", uint32(key), key>>32)
	}
	if err := p.bpfObjects.LogEnricherPids.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("error adding pid %d (ns=%d) to bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) removePID(key uint64) error {
	p.log.Debug("removing pid", "pid", uint32(key), "ns", key>>32)
	if p.bpfObjects.LogEnricherPids == nil {
		return fmt.Errorf("BPF objects not loaded, cannot remove pid %d (ns=%d)", uint32(key), key>>32)
	}
	if err := p.bpfObjects.LogEnricherPids.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("error removing pid %d (ns=%d) from bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	if fi != nil {
		p.pidServices[uint32(pid)] = fi
	}

	pk := p.pidKey(ns, uint32(pid))
	if err := p.addPID(pk); err != nil {
		p.log.Error(err.Error())
	}

	p.trackedPids[uint32(pid)] = struct{}{}
	p.registerLogPipes(uint32(pid))

	nsPids, err := procs.FindNamespacedPids(pid)
	if err != nil {
		p.log.Error("allow pid: error finding namespaced pids", "error", err)
		return
	}

	for _, nsPid := range nsPids {
		if pid == nsPid {
			continue
		}

		nsPk := p.pidKey(ns, uint32(nsPid))
		if err := p.addPID(nsPk); err != nil {
			p.log.Error(err.Error())
		}
		p.pids[pk] = append(p.pids[pk], nsPk)
	}
}

// pipe inode behind /proc/<pid>/fd/<fd>, 0 when gone or not a pipe
func statPipeIno(pid uint32, fd int) uint64 {
	var st unix.Stat_t
	if err := unix.Stat(procFdPath(pid, fd), &st); err != nil {
		return 0
	}
	if st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return 0
	}

	return st.Ino
}

// registerLogPipes records the current pipe inodes behind stdout/stderr,
// retiring registrations the process redirected away from. Callers must
// hold pidsMU
func (p *Tracer) registerLogPipes(pid uint32) {
	for _, fd := range []int{1, 2} {
		ino := statPipeIno(pid, fd)
		current := p.pidPipes[pid][fd]
		if current == ino {
			continue
		}

		if current != 0 {
			p.removePipeFD(pid, fd, current)
		}
		if ino != 0 {
			p.addPipeFD(pid, fd, ino)
		}
	}
}

// callers must hold pidsMU
func (p *Tracer) addPipeFD(pid uint32, fd int, ino uint64) {
	owners := p.logPipes[ino]
	if owners == nil {
		owners = make(map[uint32][]int)
		p.logPipes[ino] = owners

		if p.bpfObjects.LogPipes == nil {
			p.log.Error("BPF objects not loaded, cannot register log pipe", "ino", ino)
		} else if err := p.bpfObjects.LogPipes.Put(ino, uint8(1)); err != nil {
			p.log.Error("error registering log pipe in bpf map", "ino", ino, "error", err)
		}
	}
	owners[pid] = append(owners[pid], fd)

	if p.pidPipes[pid] == nil {
		p.pidPipes[pid] = make(map[int]uint64)
	}
	p.pidPipes[pid][fd] = ino
}

// callers must hold pidsMU
func (p *Tracer) removePipeFD(pid uint32, fd int, ino uint64) {
	delete(p.pidPipes[pid], fd)
	// a held write end would rob readers of EOF once the fd is gone
	p.fdCache.Remove(procFdPath(pid, fd))

	owners := p.logPipes[ino]
	if fds, ok := owners[pid]; ok {
		fds = slices.DeleteFunc(fds, func(f int) bool { return f == fd })
		if len(fds) > 0 {
			owners[pid] = fds
		} else {
			delete(owners, pid)
		}
	}
	if len(owners) > 0 {
		return
	}

	delete(p.logPipes, ino)

	if p.bpfObjects.LogPipes == nil {
		return
	}
	if err := p.bpfObjects.LogPipes.Delete(ino); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		p.log.Error("error removing log pipe from bpf map", "ino", ino, "error", err)
	}
}

// callers must hold pidsMU
func (p *Tracer) unregisterLogPipes(pid uint32) {
	for fd, ino := range p.pidPipes[pid] {
		p.removePipeFD(pid, fd, ino)
	}

	delete(p.pidPipes, pid)
}

// processes may redirect their stdio after discovery; re-stat and diff so new
// pipes get enriched and stale registrations and fd handles are retired
func (p *Tracer) reconcileLogPipes() {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	for pid := range p.trackedPids {
		p.registerLogPipes(pid)
	}
}

// deterministic order: the chosen path is the shard key, keeping lines ordered
func (p *Tracer) pipeDestCandidates(ino uint64) []string {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	owners := p.logPipes[ino]

	pids := make([]uint32, 0, len(owners))
	for pid := range owners {
		pids = append(pids, pid)
	}
	slices.Sort(pids)

	var paths []string
	for _, pid := range pids {
		for _, fd := range owners[pid] {
			paths = append(paths, procFdPath(pid, fd))
		}
	}

	return paths
}

func (p *Tracer) pipeRegistered(ino uint64) bool {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	_, ok := p.logPipes[ino]
	return ok
}

// reject the stdout fallback when it points at an unregistered pipe (app IPC)
func (p *Tracer) fallbackDestSafe(path string) bool {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return false
	}

	if st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return true
	}

	return p.pipeRegistered(st.Ino)
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	delete(p.pidServices, uint32(pid))
	delete(p.trackedPids, uint32(pid))
	p.unregisterLogPipes(uint32(pid))

	pk := p.pidKey(ns, uint32(pid))
	if err := p.removePID(pk); err != nil {
		p.log.Error(err.Error())
	}

	if knownPids, ok := p.pids[pk]; ok {
		for _, nsPk := range knownPids {
			if err := p.removePID(nsPk); err != nil {
				p.log.Error(err.Error())
			}
		}
		delete(p.pids, pk)
		return
	}

	p.log.Debug("block pid: namespaced pids not found in internal cache, removing only the given pid", "pid", pid, "ns", ns)
}

const logPipeReconcileInterval = 15 * time.Second

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("starting")

	p.ctx = ctx

	go func() {
		t := time.NewTicker(logPipeReconcileInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.reconcileLogPipes()
			}
		}
	}()

	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.LogEvents,
		p.handleLogEvent,
		nil,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)

	p.log.Debug("terminating")
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return false
}

func (p *Tracer) handleLogEvent(record *ringbuf.Record) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Offsetof(BpfLogEventT{}.Log)) // Remove `log` placeholder

	event, err := ebpfcommon.ReinterpretCast[BpfLogEventT](record.RawSample)
	if err != nil {
		// This should never happen -- if it does, we can't really recover
		// and the targeted process will miss his logs.
		return request.Span{}, true, nil
	}

	e := LogEvent{
		orig:    *event,
		logLine: unix.ByteSliceToString(record.RawSample[hdrSize : hdrSize+event.Len]),
	}

	// Open the destination now, while the writing process is still alive: the
	// open file description keeps the log pipe writable even if the process is
	// gone by the time the async writer gets to this line.
	if event.Fd != 0 {
		// address the pipe through a live owner, the writer may already be gone
		for _, candidate := range p.pipeDestCandidates(event.Ino) {
			if _, err := p.openLogDestination(candidate, event.Ino); err == nil {
				e.dest = candidate
				break
			}
		}
		if e.dest == "" {
			p.log.Debug("no live destination for log pipe, dropping line", "ino", event.Ino)
			return request.Span{}, true, nil
		}
	} else {
		e.dest = e.ttyPath()
		if unix.ByteSliceToString(event.FilePath[:]) == "" && !p.fallbackDestSafe(e.dest) {
			p.log.Debug("unsafe tty fallback destination, dropping line", "path", e.dest)
			return request.Span{}, true, nil
		}
		if _, err := p.openLogDestination(e.dest, 0); err != nil {
			p.logOpenError(e.dest, err)
			return request.Span{}, true, nil
		}
	}

	err = p.asyncWriter.Enqueue(p.ctx, e)
	return request.Span{}, true, err
}

var errStaleDestination = errors.New("destination no longer points at the captured pipe")

func fileIno(f *os.File) uint64 {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0
	}

	return st.Ino
}

// a non-zero ino pins the destination: /proc fd paths re-point when the owner
// redirects its stdio, and writing there would leak lines into the wrong file
func (p *Tracer) openLogDestination(path string, ino uint64) (*os.File, error) {
	if f, ok := p.fdCache.Get(path); ok {
		if ino == 0 || fileIno(f) == ino {
			return f, nil
		}
		p.fdCache.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	if ino != 0 && fileIno(f) != ino {
		f.Close()
		return nil, errStaleDestination
	}
	p.fdCache.Add(path, f)

	return f, nil
}

// a gone or re-pointed destination means its process died or redirected
// between writing the line and us getting to it: expected, drop quietly
func (p *Tracer) logOpenError(path string, err error) {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errStaleDestination) {
		p.log.Debug("log destination is gone, dropping line", "path", path, "error", err)
		return
	}

	p.log.Error("failed to open log file for writing", "path", path, "error", err)
}

func procFdPath(pid uint32, fd int) string {
	return filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "fd", strconv.Itoa(fd))
}

func (e LogEvent) ttyPath() string {
	fp := unix.ByteSliceToString(e.orig.FilePath[:])
	if fp == "" {
		// Fallback to process stdout in the case path resolver failed
		fp = procFdPath(e.orig.Tgid, 1)
	}

	return fp
}

func (p *Tracer) handle(e LogEvent) {
	// normally warmed at capture time; reopened only if the cache evicted it
	f, err := p.openLogDestination(e.dest, e.orig.Ino)
	if err != nil {
		p.logOpenError(e.dest, err)
		return
	}

	var (
		zeroTraceID [16]uint8
		zeroSpanID  [8]uint8
	)
	if e.orig.Ctx.TraceId == zeroTraceID || e.orig.Ctx.SpanId == zeroSpanID {
		// No trace context to inject, write original log line
		_, err := f.Write([]byte(e.logLine))
		if err != nil {
			p.log.Error("failed to write log line", "error", err)
		}
		return
	}

	spanID := trace.SpanID(e.orig.Ctx.SpanId)
	traceID := trace.TraceID(e.orig.Ctx.TraceId)
	includeSpan := !p.shouldOmitSpanID(e.orig.Tgid)

	out, err := p.formatter.format([]byte(e.logLine), traceID.String(), spanID.String(), includeSpan)
	if err != nil {
		p.log.Warn("failed to format enriched log line, writing original", "error", err)
		out = []byte(e.logLine)
	}

	_, err = f.Write(out)
	if err != nil {
		p.log.Error("failed to write enriched log line", "error", err)
	}
}
