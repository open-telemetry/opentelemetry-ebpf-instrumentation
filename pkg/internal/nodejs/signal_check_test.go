// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func findNodeBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH")
	}
	// Resolve symlinks to get the real node binary path
	nodePath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("failed to resolve node path: %v", err)
	}
	return nodePath
}

func startNodeScript(t *testing.T, script string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("node", "-e", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start node: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// Give Node.js time to initialize and register signal handlers
	time.Sleep(1 * time.Second)
	return cmd
}

func openNodeELF(t *testing.T, pid int) *elf.File {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/exe", pid)
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("failed to open ELF: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestHasUserSIGUSR1Handler_NoHandler(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/mem")
	}

	cmd := startNodeScript(t, `
		const http = require('http');
		const s = http.createServer((req, res) => res.end('ok'));
		s.listen(0, () => console.log('ready'));
		setTimeout(() => {}, 600000);
	`)

	ef := openNodeELF(t, cmd.Process.Pid)

	if hasUserSIGUSR1Handler(cmd.Process.Pid, ef) {
		t.Error("expected no SIGUSR1 handler, but one was detected")
	}
}

func TestHasUserSIGUSR1Handler_WithHandler(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/mem")
	}

	cmd := startNodeScript(t, `
		process.on('SIGUSR1', () => console.log('got sigusr1'));
		setTimeout(() => {}, 600000);
	`)

	ef := openNodeELF(t, cmd.Process.Pid)

	if !hasUserSIGUSR1Handler(cmd.Process.Pid, ef) {
		t.Error("expected SIGUSR1 handler to be detected, but it was not")
	}
}

func TestHasUserSIGUSR1Handler_OtherSignalOnly(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/mem")
	}

	cmd := startNodeScript(t, `
		process.on('SIGINT', () => { console.log('got sigint'); process.exit(0); });
		setTimeout(() => {}, 600000);
	`)

	ef := openNodeELF(t, cmd.Process.Pid)

	if hasUserSIGUSR1Handler(cmd.Process.Pid, ef) {
		t.Error("expected no SIGUSR1 handler (only SIGINT), but SIGUSR1 was detected")
	}
}

func newTestInjector(t *testing.T) *NodeInjector {
	t.Helper()
	return &NodeInjector{
		log: slog.With("component", "nodejs.Injector.test"),
	}
}

func TestIsInspectorOpen_WithInspectFlag(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for network namespace switching")
	}

	cmd := exec.Command("node", "--inspect=9229", "-e", `setTimeout(() => {}, 600000);`)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start node: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	time.Sleep(1 * time.Second)

	injector := newTestInjector(t)
	if !injector.isInspectorOpen(cmd.Process.Pid) {
		t.Error("expected isInspectorOpen to return true when node is started with --inspect")
	}
}

func TestIsInspectorOpen_WithoutInspectFlag(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for network namespace switching")
	}

	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)

	injector := newTestInjector(t)
	if injector.isInspectorOpen(cmd.Process.Pid) {
		t.Error("expected isInspectorOpen to return false when node is started without --inspect")
	}
}

func TestFindSymbolVAddr(t *testing.T) {
	nodePath := findNodeBinary(t)
	f, err := elf.Open(nodePath)
	if err != nil {
		t.Fatalf("failed to open node ELF: %v", err)
	}
	defer f.Close()

	addr, err := findSymbolVAddr(f, "uv__signal_tree")
	if err != nil {
		t.Fatalf("expected to find uv__signal_tree symbol: %v", err)
	}
	if addr == 0 {
		t.Error("expected non-zero address for uv__signal_tree")
	}
}

func TestFindSymbolVAddr_NotFound(t *testing.T) {
	nodePath := findNodeBinary(t)
	f, err := elf.Open(nodePath)
	if err != nil {
		t.Fatalf("failed to open node ELF: %v", err)
	}
	defer f.Close()

	_, err = findSymbolVAddr(f, "nonexistent_symbol_xyz")
	if err == nil {
		t.Error("expected error for nonexistent symbol")
	}
}
