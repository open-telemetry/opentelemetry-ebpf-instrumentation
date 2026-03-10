// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	_ "embed"
	"errors"
	"log/slog"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
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

func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled && (i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled())
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

	i.log.Info("loading NodeJS instrumentation", "pid", ie.FileInfo.Pid)

	if err := i.attachAgent(int(ie.FileInfo.Pid), ie.FileInfo.ELF); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", ie.FileInfo.Pid, "error", err)
		i.log.Error("trace-context propagation will not work for NodeJS services!")
	}
}

func (i *NodeInjector) attachAgent(pid int, elfFile *elf.File) error {
	// If the inspector port is already open (e.g. --inspect flag), skip SIGUSR1
	// and inject directly.
	if i.isInspectorOpen(pid) {
		i.log.Debug("Node.js inspector already open, injecting agent", "pid", pid)
		return i.inject(pid)
	}

	if elfFile != nil && hasUserSIGUSR1Handler(pid, elfFile) {
		i.log.Debug("Node.js process has a custom SIGUSR1 handler, skipping agent injection",
			"pid", pid)
		return nil
	}

	err := syscall.Kill(pid, syscall.SIGUSR1)
	if err != nil {
		i.log.Error("error enabling node inspector", "err", err)
		return errors.New("error enabling node inspector")
	}

	return i.inject(pid)
}

// isInspectorOpen checks if the Node.js inspector port (9229) is already
// accepting connections in the target process's network namespace.
// It validates that the listener is actually a Node.js inspector by
// requesting /json/version and checking for a valid response.
func (i *NodeInjector) isInspectorOpen(pid int) bool {
	open := false
	err := withNetNS(pid, func() error {
		conn, err := connect("127.0.0.1", 9229)
		if err != nil {
			return err
		}
		defer conn.Close()

		// Validate this is actually a Node.js inspector, not some other
		// service that happens to listen on port 9229.
		resp, err := httpGet(conn, "/json/version")
		if err != nil {
			return err
		}

		// The Node.js inspector responds with a JSON object containing
		// "Browser" and "Protocol-Version" fields.
		if len(resp) == 0 || resp[0] != '{' {
			return errors.New("not a Node.js inspector")
		}

		open = true
		return nil
	})
	if err != nil {
		return false
	}
	return open
}

//go:embed fdextractor.js
var _extractorBytes []byte
