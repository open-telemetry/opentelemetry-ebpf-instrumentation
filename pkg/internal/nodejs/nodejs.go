// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	_ "embed"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/obi"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config

	mu       sync.Mutex
	injected map[int]uint64
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	log := slog.With("component", "nodejs.Injector")

	if !cfg.NodeJS.Enabled && cfg.AppRuntimeMetricsEnabled() {
		log.Warn("application_runtime is enabled but the Node.js injector is disabled " +
			"(nodejs.enabled=false): Node.js runtime metrics will not be collected")
	}

	return &NodeInjector{
		cfg:      cfg,
		log:      log,
		injected: map[int]uint64{},
	}
}

// Enabled reports whether the agent should be injected: the injected script
// is both the trace-context propagation vehicle and the only source of the
// nodejs.eventloop.* runtime metrics, so either consumer turns it on —
// unless nodejs.enabled, the global opt-out, is set to false.
func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled &&
		(i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() || i.cfg.AppRuntimeMetricsEnabled())
}

// injectionTrigger names what turned the injection on, so the logs explain a
// metrics-only injection.
func (i *NodeInjector) injectionTrigger() string {
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		return "traces"
	}
	return "runtime metrics"
}

func (i *NodeInjector) NewExecutable(ie *ebpf.Instrumentable) {
	if !i.Enabled() {
		i.log.Debug("Node Injector is disabled")
		return
	}

	if ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return
	}

	pid := int(ie.FileInfo.Pid())

	i.log.Info("loading NodeJS instrumentation", "pid", pid, "trigger", i.injectionTrigger())

	// Captured before the injection so the uninjection can tell this process
	// apart from a later one that reuses its pid.
	startTime := procStartTime(pid)

	injected, err := i.attachAgent(pid, ie.FileInfo.ELF(), i.agentCode())
	if err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", pid, "error", err)
		i.log.Error("trace-context propagation and nodejs runtime metrics will not work for NodeJS services!")

		return
	}

	if injected && startTime != 0 {
		i.mu.Lock()
		i.injected[pid] = startTime
		i.mu.Unlock()
	}
}

// Forget drops a process from the uninjection set, so a pid that discovery has
// already seen exit is never signaled again.
func (i *NodeInjector) Forget(pid int) {
	i.mu.Lock()
	delete(i.injected, pid)
	i.mu.Unlock()
}

func (i *NodeInjector) attachAgent(pid int, elfFile *elf.File, code string) (bool, error) {
	var injected bool

	err := netns.WithNetNS(pid, func() error {
		var err error
		injected, err = i.injectFile(pid, elfFile, code)

		return err
	})

	return injected, err
}

// injectFile attempts to connect to the Node.js inspector and inject the
// agent. It first tries to connect directly (in case the inspector is already
// open, e.g. via --inspect flag), validating with /json/version. If that fails,
// it checks for a custom SIGUSR1 handler and either sends SIGUSR1 to open the
// inspector or bails out.
func (i *NodeInjector) injectFile(pid int, elfFile *elf.File, code string) (bool, error) {
	conn, err := connect("127.0.0.1", 9229)
	if err == nil {
		// Validate this is actually a Node.js inspector, not some other
		// service that happens to listen on port 9229.
		if i.isNodeInspector(conn) {
			i.log.Debug("Node.js inspector already open, injecting directly", "pid", pid)

			if err := i.injectViaConn(conn, code); err != nil {
				return false, err
			}

			return true, nil
		}
		conn.Close()
	}

	if elfFile != nil {
		switch hasUserSIGUSR1Handler(pid, elfFile) {
		case signalCheckFound:
			i.log.Warn("Node.js process has a custom SIGUSR1 handler, skipping agent injection. "+
				"Node.js trace correlation will not work", "pid", pid)
			return false, nil
		case signalCheckFailed:
			// Symbol-based detection failed (e.g. stripped binary with dynamic libuv).
			// Fall back to scanning the application's source files for quoted SIGUSR1 references.
			if sourceHasSIGUSR1Reference(pid) {
				i.log.Warn("Node.js source files reference SIGUSR1, skipping agent injection. "+
					"Node.js trace correlation will not work", "pid", pid)
				return false, nil
			}
		case signalCheckNotFound:
			// No handler detected, safe to proceed.
		}
	}

	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		return false, fmt.Errorf("error enabling node inspector: %w", err)
	}

	conn, err = connectWait("127.0.0.1", 9229, 5*time.Second, 200*time.Millisecond)
	if err != nil {
		return false, fmt.Errorf("failed to connect to inspector after SIGUSR1: %w", err)
	}

	if err := i.injectViaConn(conn, code); err != nil {
		return false, err
	}

	return true, nil
}

// isNodeInspector validates that a connection to port 9229 is actually a
// Node.js inspector by requesting /json/version and checking for a valid
// JSON response.
func (i *NodeInjector) isNodeInspector(conn net.Conn) bool {
	resp, err := httpGet(conn, "/json/version")
	if err != nil {
		return false
	}

	// The Node.js inspector responds with a JSON object containing
	// "Browser" and "Protocol-Version" fields.
	return len(resp) > 0 && resp[0] == '{'
}

//go:embed fdextractor.js
var _extractorCode string

//go:embed spanbridge.js
var _spanBridgeCode string

// Substituted at injection time so each injection installs only the
// machinery its configuration asks for (see the OBI_RT_ENABLED and
// OBI_TRACES_ENABLED comments in fdextractor.js).
const (
	rtEnabledPlaceholder     = "= false; /*OBI_RT_ENABLED*/"
	rtEnabledOn              = "= true; /*OBI_RT_ENABLED*/"
	tracesEnabledPlaceholder = "= false; /*OBI_TRACES_ENABLED*/"
	tracesEnabledOn          = "= true; /*OBI_TRACES_ENABLED*/"
	spansEnabledPlaceholder  = "= false; /*OBI_SPANS_ENABLED*/"
	spansEnabledOn           = "= true; /*OBI_SPANS_ENABLED*/"
)

// agentCode returns the extractor script with the RT gate substituted from
// the same predicate that sets the nodejs_runtime_metrics_enabled BPF
// constant, so the agent and the eBPF side cannot disagree. When manual
// spans are enabled the span bridge is appended as a second script: both are
// self-contained IIFEs, joined with an explicit ';' so the bridge's leading
// '(' is not parsed as a call of the extractor IIFE's return value.
func (i *NodeInjector) agentCode() string {
	code := _extractorCode
	if i.cfg.AppRuntimeMetricsEnabled() {
		code = strings.Replace(code, rtEnabledPlaceholder, rtEnabledOn, 1)
	}
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		code = strings.Replace(code, tracesEnabledPlaceholder, tracesEnabledOn, 1)
	}
	if i.cfg.NodeJS.ManualSpans {
		code += ";\n" + strings.Replace(_spanBridgeCode, spansEnabledPlaceholder, spansEnabledOn, 1)
	}

	return code
}

// uninstallCode is both scripts with every gate left off. Each one's prologue
// undoes what a previous injection installed — the extractor restores the net
// prototypes it wrapped and clears the async hook, sampling timer, delay
// histogram and GC observer; the bridge restores Module._load and the api
// setters it wrapped, and stops emitting. What survives either way is a
// delegate already cached by a ProxyTracer, which is inert once the bridge has
// stopped emitting.
func uninstallCode() string {
	return _extractorCode + ";\n" + _spanBridgeCode
}

const (
	uninjectTimeout     = 15 * time.Second
	uninjectConcurrency = 4
)

// UninjectAll removes the injected script from every process this agent
// injected. It runs on the way out, when the caller's context is already
// cancelled, so it carries its own deadline rather than deriving one.
func (i *NodeInjector) UninjectAll() {
	i.mu.Lock()
	targets := i.injected
	i.injected = map[int]uint64{}
	i.mu.Unlock()

	if !i.cfg.NodeJS.UninjectOnShutdown || len(targets) == 0 {
		return
	}

	i.log.Info("removing NodeJS instrumentation before shutdown", "processes", len(targets))

	deadline := time.Now().Add(uninjectTimeout)
	sem := make(chan struct{}, uninjectConcurrency)

	var wg sync.WaitGroup

	for pid, startTime := range targets {
		if time.Now().After(deadline) {
			i.log.Warn("timed out removing NodeJS instrumentation; "+
				"the injected script stays resident until the application restarts", "pid", pid)

			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if err := i.uninject(pid, startTime); err != nil {
				i.log.Warn("couldn't remove NodeJS instrumentation; "+
					"the injected script stays resident until the application restarts",
					"pid", pid, "error", err)
			}
		}()
	}

	wg.Wait()
}

func (i *NodeInjector) uninject(pid int, startTime uint64) error {
	return netns.WithNetNS(pid, func() error {
		conn, err := connect("127.0.0.1", 9229)
		if err == nil {
			if i.isNodeInspector(conn) {
				return i.injectViaConn(conn, uninstallCode())
			}
			conn.Close()
		}

		if err := signalInspectorOpen(pid, startTime); err != nil {
			return err
		}

		conn, err = connectWait("127.0.0.1", 9229, 5*time.Second, 200*time.Millisecond)
		if err != nil {
			return fmt.Errorf("failed to connect to inspector after SIGUSR1: %w", err)
		}

		return i.injectViaConn(conn, uninstallCode())
	})
}
