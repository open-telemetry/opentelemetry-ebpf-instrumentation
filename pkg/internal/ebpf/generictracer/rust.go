// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	lru "github.com/hashicorp/golang-lru/v2"

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
	tracer      *Tracer
	mu          sync.Mutex
	targets     map[app.PID]*rustTarget
	closed      bool
	attaching   sync.WaitGroup
	executables *lru.Cache[rustExecutableKey, *rustExecutable]
}

// rustAttachment is prepared without the controller lock. Only the PID's current
// target may publish it, because the BPF maps it writes are keyed by PID alone.
type rustAttachment struct {
	links             []io.Closer
	capabilities      BpfRustCapabilitiesT
	protocol          *BpfRustProtocolConfigT
	expectedStartTime uint64
}

func newRustController(tracer *Tracer) *rustController {
	return &rustController{
		tracer:      tracer,
		targets:     map[app.PID]*rustTarget{},
		executables: newRustExecutableCache(),
	}
}

func (c *rustController) allow(pid app.PID, fi *exec.FileInfo) {
	if fi == nil || fi.SDKLanguage() != svc.InstrumentableRust || fi.StartTime() == 0 {
		return
	}

	target := c.register(pid, fi)
	if target == nil {
		return
	}
	defer c.attaching.Done()

	// Reading the executable and attaching uprobes is slow: other PIDs must not wait on it.
	attachment, err := c.attach(pid, fi)
	c.commit(pid, target, attachment, err)
}

// register claims the PID for a new lifecycle, or returns nil when there is nothing to attach.
func (c *rustController) register(pid app.PID, fi *exec.FileInfo) *rustTarget {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.tracer.bpfObjects.RustCapabilities == nil {
		return nil
	}

	if target := c.targets[pid]; target != nil {
		if target.lifecycle == fi {
			return nil
		}
		c.remove(pid)
	}

	// Remember unsupported binaries too, so discovery does not rescan them.
	target := &rustTarget{lifecycle: fi}
	c.targets[pid] = target
	c.attaching.Add(1)

	return target
}

// commit publishes an attachment only while its target still owns the PID. A PID
// blocked, replaced or closed during attachment only gets its new probes closed.
func (c *rustController) commit(pid app.PID, target *rustTarget, attachment rustAttachment, cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.targets[pid] != target {
		closeRustLinks(attachment.links)
		return
	}

	if err := c.publish(pid, attachment); err != nil {
		_ = c.tracer.bpfObjects.RustCapabilities.Delete(uint32(pid))
		_ = c.tracer.bpfObjects.RustProtocolConfigs.Delete(uint32(pid))
		closeRustLinks(attachment.links)
		cause = errors.Join(cause, err)
	} else {
		target.links = attachment.links
		if attachment.protocol != nil {
			c.logPublished(pid, attachment)
		}
	}

	if cause != nil {
		c.tracer.log.Debug("Rust context propagation unavailable", "pid", pid, "error", cause)
	}
}

func (c *rustController) publish(pid app.PID, attachment rustAttachment) error {
	if attachment.protocol == nil {
		return nil
	}

	objects := &c.tracer.bpfObjects
	if err := objects.RustProtocolConfigs.Put(uint32(pid), *attachment.protocol); err != nil {
		return err
	}

	if err := checkRustLifecycle(pid, attachment.expectedStartTime); err != nil {
		return err
	}

	return objects.RustCapabilities.Put(uint32(pid), attachment.capabilities)
}

func (c *rustController) logPublished(pid app.PID, attachment rustAttachment) {
	capabilities := attachment.capabilities
	protocol := attachment.protocol

	c.tracer.log.Info("Enabled Rust instrumentation", "pid", pid, "tokio", capabilities.TokioRuntime != 0,
		"task_context", capabilities.TaskContext != 0, "client_context", capabilities.ClientContext != 0,
		"http1", protocol.Http1 != 0, "http2", protocol.Http2 != 0,
		"http2_server_context", protocol.H2Server != 0, "rustls", protocol.Rustls != 0)
}

func closeRustLinks(links []io.Closer) {
	for _, closer := range links {
		_ = closer.Close()
	}
}

// attach does the slow per-executable work without writing any BPF map.
func (c *rustController) attach(pid app.PID, fi *exec.FileInfo) (rustAttachment, error) {
	expectedStartTime := fi.StartTime()
	if pid != fi.Pid() {
		// Grouped workers share their parent's executable and service FileInfo.
		childStartTime, err := procs.StartTime(pid)
		if err != nil {
			return rustAttachment{}, err
		}
		expectedStartTime = childStartTime
	}

	target, err := fi.OpenExecutable()
	if err != nil {
		return rustAttachment{}, err
	}

	defer target.Close()

	// Replicas and forked workers of one binary reuse its symbol and layout analysis.
	executable := analyzeRustExecutable(c.executables, target)
	if executable.protocol == nil {
		return rustAttachment{}, executable.err
	}

	if executable.err != nil {
		c.tracer.log.Debug("Partial Rust protocol layout support", "pid", pid, "error", executable.err)
	}

	probes := executable.probes
	protocol := *executable.protocol
	groups := planRustProbes(probes, protocol)
	path := fmt.Sprintf("/proc/self/fd/%d", target.Fd())

	exe, err := link.OpenExecutable(path)
	if err != nil {
		return rustAttachment{}, err
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
		{rustTaskSpawnPublic, objects.ObiRustTaskSpawnRet, true},
		{rustTaskSpawnPublic, objects.ObiRustTaskSpawn, false},
		{rustTaskSchedule, objects.ObiRustTaskSchedule, false},
		{rustTaskScheduleLocal, objects.ObiRustTaskScheduleLocal, false},

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

	if (!features["h2-send"] || !features["h2-driver"]) && protocol.H2Server == 0 {
		protocol.Http2 = 0
	}

	// Binding hides the connection's ciphertext from generic capture, so its plaintext
	// must be captured in both directions or the connection's spans never complete.
	if !features["tls-bind"] || !features["tls-read"] || !features["tls-write"] {
		protocol.Rustls = 0
	}

	// HTTP/1 requires task context. HTTP/2 and Rustls can also observe protocol data independently.
	if capabilities.TaskContext == 0 && protocol.Http2 == 0 && protocol.Rustls == 0 {
		closeRustLinks(links)
		return rustAttachment{}, errors.Join(errors.New("no usable Rust runtime or protocol probes"), attachErr)
	}

	if capabilities.ClientContext != 0 && c.tracer.cfg.EBPF.ContextPropagation.HasHeaders() {
		protocol.Inject = 1
	}

	return rustAttachment{
		links:             links,
		capabilities:      capabilities,
		protocol:          &protocol,
		expectedStartTime: expectedStartTime,
	}, nil
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

// Close waits for attachments in progress: their commits close the probes they
// attached, before the tracer closes the BPF programs those probes use.
func (c *rustController) Close() error {
	c.mu.Lock()
	c.closed = true

	for pid := range c.targets {
		c.remove(pid)
	}
	c.mu.Unlock()

	c.attaching.Wait()

	return nil
}
