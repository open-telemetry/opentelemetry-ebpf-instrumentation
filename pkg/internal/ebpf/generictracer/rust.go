// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type rustTarget struct {
	lifecycle *exec.FileInfo
	links     []io.Closer
}

type rustController struct {
	tracer  *Tracer
	mu      sync.Mutex
	targets map[app.PID]*rustTarget
	closed  bool
}

func newRustController(tracer *Tracer) *rustController {
	return &rustController{tracer: tracer, targets: map[app.PID]*rustTarget{}}
}

func (c *rustController) allow(pid app.PID, fi *exec.FileInfo) {
	if fi == nil || fi.SDKLanguage() != svc.InstrumentableRust || fi.StartTime() == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.tracer.bpfObjects.RustCapabilities == nil {
		return
	}

	if target := c.targets[pid]; target != nil {
		if target.lifecycle == fi {
			return
		}
		c.remove(pid)
	}

	// Remember unsupported binaries too, so discovery does not rescan them.
	target := &rustTarget{lifecycle: fi}
	c.targets[pid] = target
	links, err := c.attach(pid, fi)

	if err != nil {
		c.tracer.log.Debug("Rust context propagation unavailable", "pid", pid, "error", err)
		return
	}

	target.links = links
}

func (c *rustController) attach(pid app.PID, fi *exec.FileInfo) ([]io.Closer, error) {
	expectedStartTime := fi.StartTime()
	if pid != fi.Pid() {
		// Grouped workers share their parent's executable and service FileInfo.
		childStartTime, err := procs.StartTime(pid)
		if err != nil {
			return nil, err
		}
		expectedStartTime = childStartTime
	}

	target, err := fi.OpenExecutable()
	if err != nil {
		return nil, err
	}

	defer target.Close()

	f, err := elf.NewFile(target)
	if err != nil {
		return nil, err
	}

	probes, err := resolveRustProbes(f)
	if err != nil {
		return nil, c.keepTokioRuntime(pid, expectedStartTime, probes, err)
	}

	protocol, layoutErr := resolveRustProtocolLayouts(f, probes.layoutChannels()...)
	if layoutErr != nil {
		c.tracer.log.Debug("Partial Rust protocol layout support", "pid", pid, "error", layoutErr)
	}

	groups := planRustProbes(probes, protocol)
	path := fmt.Sprintf("/proc/self/fd/%d", target.Fd())

	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}

	objects := &c.tracer.bpfObjects
	programs := []struct {
		kind    rustProbeKind
		program *ebpf.Program
		ret     bool
	}{
		{rustTaskPoll, objects.ObiRustTaskPollRet, true},
		{rustTaskHarnessPoll, objects.ObiRustTaskPollRet, true},
		{rustTaskHarnessPoll, objects.ObiRustTaskPoll, false},
		{rustTaskHarnessDealloc, objects.ObiRustTaskDealloc, false},
		{rustTaskNew, objects.ObiRustTaskNew, true},
		{rustTaskRawNew, objects.ObiRustTaskNew, true},
		{rustTaskBind, objects.ObiRustTaskBind, false},
		{rustTaskPublish, objects.ObiRustTaskBind, false},
		{rustTaskSpawn, objects.ObiRustTaskSpawnRet, true},
		{rustTaskSpawn, objects.ObiRustTaskSpawn, false},
		{rustTaskSchedule, objects.ObiRustTaskSchedule, false},

		{rustHyperFindBlock, objects.ObiRustHyperFindBlockRet, true},
		{rustHyperFindBlock, objects.ObiRustHyperFindBlock, false},
		{rustHyperPop, objects.ObiRustHyperPopRet, true},
		{rustHyperPop, objects.ObiRustHyperPop, false},
		{rustHyperSend, objects.ObiRustHyperSend, false},
		{rustHyperRequestSend, objects.ObiRustHyperRequestSend, false},
		{rustHyperRequestReceive, objects.ObiRustHyperRequestReceiveRet, true},
		{rustHyperRequestReceive, objects.ObiRustHyperReceive, false},
		{rustHyperClear, objects.ObiRustHyperClear, false},
		{rustHyperChanSend, objects.ObiRustHyperSend, false},
		{rustHyperReceive, objects.ObiRustHyperReceiveRet, true},
		{rustHyperReceive, objects.ObiRustHyperReceive, false},
		{rustTaskDealloc, objects.ObiRustTaskDealloc, false},
		{rustHyperEnqueue, objects.ObiRustHyperEnqueue, false},
		{rustHyperDequeue, objects.ObiRustHyperDequeue, false},

		{rustTLSFlush, objects.ObiRustlsFlushRet, true},
		{rustTLSFlush, objects.ObiRustlsFlush, false},
		{rustTLSFlushBuffer, objects.ObiRustlsFlushRet, true},
		{rustTLSFlushBuffer, objects.ObiRustlsFlushBuffer, false},
		{rustTLSClientProcess, objects.ObiRustlsProcessRet, true},
		{rustTLSClientProcess, objects.ObiRustlsProcessClient, false},
		{rustTLSServerProcess, objects.ObiRustlsProcessRet, true},
		{rustTLSServerProcess, objects.ObiRustlsProcessServer, false},
		{rustTLSClientLegacyProcess, objects.ObiRustlsProcessRet, true},
		{rustTLSClientLegacyProcess, objects.ObiRustlsProcessClient, false},
		{rustTLSServerLegacyProcess, objects.ObiRustlsProcessRet, true},
		{rustTLSServerLegacyProcess, objects.ObiRustlsProcessServer, false},
		{rustTLSChunk, objects.ObiRustlsFirstChunkRet, true},
		{rustTLSChunk, objects.ObiRustlsFirstChunk, false},
		{rustTLSConsume, objects.ObiRustlsConsume, false},
		{rustTLSReaderRead, objects.ObiRustlsReadRet, true},
		{rustTLSReaderRead, objects.ObiRustlsReaderRead, false},
		{rustTLSRead, objects.ObiRustlsReadRet, true},
		{rustTLSRead, objects.ObiRustlsRead, false},
		{rustTLSWrite, objects.ObiRustlsWriteRet, true},
		{rustTLSWrite, objects.ObiRustlsWrite, false},
		{rustTLSWriteVectored, objects.ObiRustlsWriteRet, true},
		{rustTLSWriteVectored, objects.ObiRustlsWriteVectored, false},

		{rustHTTP1Headers, objects.ObiRustHttp1HeadersRet, true},
		{rustHTTP1Headers, objects.ObiRustHttp1Headers, false},
		{rustHTTP1HeadersOriginal, objects.ObiRustHttp1HeadersRet, true},
		{rustHTTP1HeadersOriginal, objects.ObiRustHttp1HeadersOriginal, false},

		{rustH2SendHeaders, objects.ObiRustH2SendHeaders, false},
		{rustH2BufferPending, objects.ObiRustH2BufferPendingRet, true},
		{rustH2BufferPending, objects.ObiRustH2BufferPending, false},
		{rustH2PollComplete, objects.ObiRustH2BufferPendingRet, true},
		{rustH2PollComplete, objects.ObiRustH2PollComplete, false},
		{rustH2PrioritizePending, objects.ObiRustH2BufferPendingRet, true},
		{rustH2PrioritizePending, objects.ObiRustH2PrioritizePending, false},
		{rustH2PrioritizeComplete, objects.ObiRustH2BufferPendingRet, true},
		{rustH2PrioritizeComplete, objects.ObiRustH2PrioritizeComplete, false},
		{rustH2Encode, objects.ObiRustH2EncodeRet, true},
		{rustH2Encode, objects.ObiRustH2Encode, false},
		{rustH2TakeRequest, objects.ObiRustH2TakeRequestRet, true},
		{rustH2TakeRequest, objects.ObiRustH2TakeRequest, false},
		{rustH2TakeStreamRequest, objects.ObiRustH2TakeRequestRet, true},
		{rustH2TakeStreamRequest, objects.ObiRustH2TakeStreamRequest, false},
		{rustH2HPACK, objects.ObiRustH2HpackRet, true},
		{rustH2HPACK, objects.ObiRustH2Hpack, false},
		{rustTaskPoll, objects.ObiRustTaskPoll, false},
	}

	attachAlternative := func(alternative rustProbeAlternative) ([]io.Closer, error) {
		var attached []io.Closer
		for _, probe := range programs {
			addresses := alternative[probe.kind]
			if len(addresses) == 0 {
				continue
			}

			l, err := uprobe.Attach(exe, path, probe.program, uprobe.Options{
				Addresses: addresses, PID: uint32(pid), Return: probe.ret,
			})

			if err != nil {
				return attached, err
			}
			attached = append(attached, l)
		}

		return attached, nil
	}

	links, features, attachErr := attachRustGroups(groups, attachAlternative)
	cleared, clearFeatures, clearErr := attachRustGroups(planRustChannelClears(probes, features), attachAlternative)
	links = append(links, cleared...)
	maps.Copy(features, clearFeatures)
	attachErr = errors.Join(attachErr, clearErr)

	if attachErr != nil {
		c.tracer.log.Debug("Partial Rust probe attachment", "pid", pid, "error", attachErr)
	}

	rollback := func() {
		_ = objects.RustCapabilities.Delete(uint32(pid))
		_ = objects.RustProtocolConfigs.Delete(uint32(pid))
		for _, closer := range links {
			_ = closer.Close()
		}
	}

	if len(links) == 0 {
		return nil, c.keepTokioRuntime(pid, expectedStartTime, probes, errors.New("no Rust probe group could be attached"))
	}

	capabilities := BpfRustCapabilitiesT{}
	if probes.hasTokio {
		capabilities.TokioRuntime = 1
	}

	if features["task-poll"] && (features["task-create"] || features["task-dealloc"]) {
		capabilities.TaskContext = 1
		complete := !probes.hasHyper || len(probes.channels) > 0
		supported := !probes.hasHyper

		for _, channel := range probes.channels {
			complete = complete && (features["channel:"+channel] || features["channel-clear:"+channel])
			supported = supported || features["channel:"+channel]
		}

		if complete && supported {
			capabilities.ClientContext = 1
		}
	}

	if !features["http1"] {
		protocol.Http1 = 0
	}

	if !features["h2-server"] || capabilities.TaskContext == 0 {
		protocol.H2Server = 0
	}

	if !features["h2-hpack"] {
		protocol.H2Hpack = 0
	}

	if (!features["h2-send"] || !features["h2-driver"]) && !features["h2-server"] {
		protocol.Http2 = 0
	}

	if !features["tls-process"] || !features["tls-io"] {
		protocol.Rustls = 0
	}

	if capabilities.ClientContext != 0 && c.tracer.cfg.EBPF.ContextPropagation.HasHeaders() {
		protocol.Inject = 1
	}

	if err := objects.RustProtocolConfigs.Put(uint32(pid), protocol); err != nil {
		rollback()
		return nil, err
	}

	if err := checkRustLifecycle(pid, expectedStartTime); err != nil {
		rollback()
		return nil, err
	}

	if err := objects.RustCapabilities.Put(uint32(pid), capabilities); err != nil {
		rollback()
		return nil, err
	}

	c.tracer.log.Info("Enabled Rust instrumentation", "pid", pid, "tokio", probes.hasTokio,
		"task_context", capabilities.TaskContext != 0, "client_context", capabilities.ClientContext != 0,
		"http1", protocol.Http1 != 0, "http2", protocol.Http2 != 0,
		"http2_server_context", protocol.H2Server != 0, "rustls", protocol.Rustls != 0)

	return links, nil
}

// keepTokioRuntime publishes only the runtime marker when no Rust hook is usable.
// Tokio workers still poll unrelated tasks, so their threads must not supply parents.
func (c *rustController) keepTokioRuntime(pid app.PID, expectedStartTime uint64, probes rustProbeSymbols, cause error) error {
	if !probes.hasTokio {
		return cause
	}

	if err := checkRustLifecycle(pid, expectedStartTime); err != nil {
		return errors.Join(cause, err)
	}

	marker := BpfRustCapabilitiesT{TokioRuntime: 1}
	if err := c.tracer.bpfObjects.RustCapabilities.Put(uint32(pid), marker); err != nil {
		return errors.Join(cause, err)
	}

	c.tracer.log.Info("Tokio runtime without usable Rust hooks; worker-thread parents disabled",
		"pid", pid, "reason", cause)

	return cause
}

// checkRustLifecycle rejects a PID that no longer runs the process discovery saw.
func checkRustLifecycle(pid app.PID, expectedStartTime uint64) error {
	startTime, err := procs.StartTime(pid)
	if err != nil {
		return err
	}

	if startTime != expectedStartTime {
		return errors.New("rust process lifecycle changed during attachment")
	}

	return nil
}

func (c *rustController) block(pid app.PID, fi *exec.FileInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if target := c.targets[pid]; target != nil && (fi == nil || target.lifecycle == fi) {
		c.remove(pid)
	}
}

func (c *rustController) remove(pid app.PID) {
	if c.tracer.bpfObjects.RustCapabilities != nil {
		_ = c.tracer.bpfObjects.RustCapabilities.Delete(uint32(pid))
	}

	if c.tracer.bpfObjects.RustProtocolConfigs != nil {
		_ = c.tracer.bpfObjects.RustProtocolConfigs.Delete(uint32(pid))
	}

	for _, closer := range c.targets[pid].links {
		_ = closer.Close()
	}

	delete(c.targets, pid)
}

func (c *rustController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true

	for pid := range c.targets {
		c.remove(pid)
	}

	return nil
}
