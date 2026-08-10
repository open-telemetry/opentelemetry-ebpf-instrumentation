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
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	return &NodeInjector{
		cfg: cfg,
		log: slog.With("component", "nodejs.Injector"),
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

	i.log.Info("loading NodeJS instrumentation", "pid", ie.FileInfo.Pid(), "trigger", i.injectionTrigger())

	if err := i.attachAgent(int(ie.FileInfo.Pid()), ie.FileInfo.ELF()); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", ie.FileInfo.Pid(), "error", err)
		i.log.Error("trace-context propagation and nodejs runtime metrics will not work for NodeJS services!")
	}
}

func (i *NodeInjector) attachAgent(pid int, elfFile *elf.File) error {
	return netns.WithNetNS(pid, func() error {
		return i.injectFile(pid, elfFile)
	})
}

// injectFile attempts to connect to the Node.js inspector and inject the
// agent. It first tries to connect directly (in case the inspector is already
// open, e.g. via --inspect flag), validating with /json/version. If that fails,
// it checks for a custom SIGUSR1 handler and either sends SIGUSR1 to open the
// inspector or bails out.
func (i *NodeInjector) injectFile(pid int, elfFile *elf.File) error {
	conn, err := connect("127.0.0.1", 9229)
	if err == nil {
		// Validate this is actually a Node.js inspector, not some other
		// service that happens to listen on port 9229.
		if i.isNodeInspector(conn) {
			i.log.Debug("Node.js inspector already open, injecting directly", "pid", pid)
			return i.injectViaConn(conn)
		}
		conn.Close()
	}

	if elfFile != nil {
		switch hasUserSIGUSR1Handler(pid, elfFile) {
		case signalCheckFound:
			i.log.Warn("Node.js process has a custom SIGUSR1 handler, skipping agent injection. "+
				"Node.js trace correlation will not work", "pid", pid)
			return nil
		case signalCheckFailed:
			// Symbol-based detection failed (e.g. stripped binary with dynamic libuv).
			// Fall back to scanning the application's source files for quoted SIGUSR1 references.
			if sourceHasSIGUSR1Reference(pid) {
				i.log.Warn("Node.js source files reference SIGUSR1, skipping agent injection. "+
					"Node.js trace correlation will not work", "pid", pid)
				return nil
			}
		case signalCheckNotFound:
			// No handler detected, safe to proceed.
		}
	}

	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		return fmt.Errorf("error enabling node inspector: %w", err)
	}

	conn, err = connectWait("127.0.0.1", 9229, 5*time.Second, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to connect to inspector after SIGUSR1: %w", err)
	}

	return i.injectViaConn(conn)
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

// rtEnabledPlaceholder is substituted at injection time so a traces-only
// injection never installs the runtime-metrics sampling machinery in the
// target process (see the RT_ENABLED comment in fdextractor.js).
const (
	rtEnabledPlaceholder = "= false; /*OBI_RT_ENABLED*/"
	rtEnabledOn          = "= true; /*OBI_RT_ENABLED*/"
)

// agentCode returns the extractor script with the runtime-metrics gate set
// from the same config gate that drives the nodejs_runtime_metrics_enabled
// BPF constant, so the agent and the decoder cannot disagree.
func (i *NodeInjector) agentCode() string {
	if !i.cfg.AppRuntimeMetricsEnabled() {
		return _extractorCode
	}
	return strings.Replace(_extractorCode, rtEnabledPlaceholder, rtEnabledOn, 1)
}
