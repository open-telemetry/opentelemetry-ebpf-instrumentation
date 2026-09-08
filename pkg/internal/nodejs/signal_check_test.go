// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
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

// startNodeApp runs a script from a file so the process has a resolvable
// application directory, which "node -e" does not.
func startNodeApp(t *testing.T, script string) *exec.Cmd {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cmd := exec.Command("node", "app.js")
	cmd.Dir = dir
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

	result := hasUserSIGUSR1Handler(cmd.Process.Pid, ef)
	if result != signalCheckNotFound {
		t.Errorf("expected signalCheckNotFound, got %d", result)
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

	result := hasUserSIGUSR1Handler(cmd.Process.Pid, ef)
	if result != signalCheckFound {
		t.Errorf("expected signalCheckFound, got %d", result)
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

	result := hasUserSIGUSR1Handler(cmd.Process.Pid, ef)
	if result != signalCheckNotFound {
		t.Errorf("expected signalCheckNotFound, got %d", result)
	}
}

func TestFindExeBaseAddr(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/maps")
	}

	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)
	pid := cmd.Process.Pid

	base, err := procs.FindExeBaseAddr(app.PID(pid))
	if err != nil {
		t.Fatalf("findExeBaseAddr failed: %v", err)
	}

	ef := openNodeELF(t, pid)

	if ef.Type == elf.ET_DYN {
		// PIE binary: base should be non-zero (ASLR puts it somewhere in memory)
		if base == 0 {
			t.Error("expected non-zero base address for PIE binary")
		}
		t.Logf("PIE binary: base address = 0x%x", base)
	} else {
		// Non-PIE (ET_EXEC): base should match the ELF's lowest PT_LOAD vaddr
		// (typically 0x400000 on x86-64)
		if base == 0 {
			t.Error("expected non-zero base address")
		}
		t.Logf("non-PIE binary: base address = 0x%x", base)
	}
}

func TestFindExeBaseAddr_InvalidPid(t *testing.T) {
	_, err := procs.FindExeBaseAddr(99999999)
	if err == nil {
		t.Error("expected error for invalid pid")
	}
}

func TestFindExeSymbols_SignalTree(t *testing.T) {
	nodePath := findNodeBinary(t)
	f, err := elf.Open(nodePath)
	if err != nil {
		t.Fatalf("failed to open node ELF: %v", err)
	}
	defer f.Close()

	syms, err := procs.FindExeSymbols(f, []string{"uv__signal_tree"}, elf.STT_OBJECT)
	if err != nil {
		t.Fatalf("FindExeSymbols failed: %v", err)
	}
	sym, ok := syms["uv__signal_tree"]
	if !ok {
		t.Fatal("expected to find uv__signal_tree symbol")
	}
	if sym.Off == 0 {
		t.Error("expected non-zero address for uv__signal_tree")
	}
}

func TestFindExeSymbols_NotFound(t *testing.T) {
	nodePath := findNodeBinary(t)
	f, err := elf.Open(nodePath)
	if err != nil {
		t.Fatalf("failed to open node ELF: %v", err)
	}
	defer f.Close()

	syms, err := procs.FindExeSymbols(f, []string{"nonexistent_symbol_xyz"}, elf.STT_OBJECT)
	if err != nil {
		t.Fatalf("FindExeSymbols failed: %v", err)
	}
	if _, ok := syms["nonexistent_symbol_xyz"]; ok {
		t.Error("expected symbol not to be found")
	}
}

func openELFPath(t *testing.T, path string) *elf.File {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("failed to open ELF %s: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func testBinaryELF(t *testing.T) *elf.File {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to locate test binary: %v", err)
	}
	return openELFPath(t, path)
}

func unusedPID(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Skipf("cannot read pid_max: %v", err)
	}
	pidMax, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Skipf("cannot parse pid_max: %v", err)
	}
	return pidMax + 1
}

func TestIsNodeRuntime_NilELF(t *testing.T) {
	if isNodeRuntime(os.Getpid(), nil) {
		t.Error("expected a nil ELF not to be identified as a Node.js runtime")
	}
}

func TestIsNodeRuntime_NodeBinary(t *testing.T) {
	if !isNodeRuntime(os.Getpid(), openELFPath(t, findNodeBinary(t))) {
		t.Error("expected the node binary to be identified as a Node.js runtime")
	}
}

func TestIsNodeRuntime_NonNodeExecutable(t *testing.T) {
	if isNodeRuntime(os.Getpid(), testBinaryELF(t)) {
		t.Error("expected a non-Node executable not to be identified as a Node.js runtime")
	}
}

func TestHasMappedNodeLibrary_NonNodeProcess(t *testing.T) {
	if hasMappedNodeLibrary(os.Getpid()) {
		t.Error("expected no libnode.so mapping in a non-Node process")
	}
}

func TestSigusr1Disposition_NodeCatchesSignal(t *testing.T) {
	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)

	if got := sigusr1Disposition(cmd.Process.Pid); got != signalDispositionHandled {
		t.Errorf("expected signalDispositionHandled for a Node process, got %d", got)
	}
}

func TestSigusr1Disposition_FatalWithoutHandler(t *testing.T) {
	cmd := exec.Command("sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	if got := sigusr1Disposition(cmd.Process.Pid); got != signalDispositionFatal {
		t.Errorf("expected signalDispositionFatal for a process with no SIGUSR1 handler, got %d", got)
	}
}

func TestSigusr1Disposition_UnknownForDeadProcess(t *testing.T) {
	if got := sigusr1Disposition(unusedPID(t)); got != signalDispositionUnknown {
		t.Errorf("expected signalDispositionUnknown for a nonexistent pid, got %d", got)
	}
}

func TestSignalTreeRuntimeAddr_ResolvesForNode(t *testing.T) {
	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)

	addr, ok := signalTreeRuntimeAddr(cmd.Process.Pid, openNodeELF(t, cmd.Process.Pid))
	if !ok {
		t.Fatal("expected uv__signal_tree to resolve for a Node process")
	}
	if addr == 0 {
		t.Error("expected a non-zero runtime address")
	}
}

func TestSIGUSR1Refusal_NonNodeExecutable(t *testing.T) {
	reason := sigusr1Refusal(os.Getpid(), testBinaryELF(t))
	if reason != refusalNotNodeRuntime {
		t.Errorf("expected %q, got %q", refusalNotNodeRuntime, reason)
	}
}

func TestSIGUSR1Refusal_NilELF(t *testing.T) {
	reason := sigusr1Refusal(os.Getpid(), nil)
	if reason != refusalNotNodeRuntime {
		t.Errorf("expected %q, got %q", refusalNotNodeRuntime, reason)
	}
}

func TestSIGUSR1Refusal_DispositionUnreadable(t *testing.T) {
	reason := sigusr1Refusal(unusedPID(t), openELFPath(t, findNodeBinary(t)))
	if reason != refusalDispositionUnknown {
		t.Errorf("expected %q, got %q", refusalDispositionUnknown, reason)
	}
}

func TestSIGUSR1Refusal_SignalWouldBeFatal(t *testing.T) {
	cmd := exec.Command("sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	reason := sigusr1Refusal(cmd.Process.Pid, openELFPath(t, findNodeBinary(t)))
	if reason != refusalSignalIsFatal {
		t.Errorf("expected %q, got %q", refusalSignalIsFatal, reason)
	}
}

func TestSourceScanRefusal_AppReferencingSIGUSR1(t *testing.T) {
	cmd := startNodeApp(t, `
process.on("SIGUSR1", () => console.log('reload'));
setTimeout(() => {}, 600000);
`)

	if reason := sourceScanRefusal(cmd.Process.Pid); reason != refusalSourceReferencesSIGUSR1 {
		t.Errorf("expected %q, got %q", refusalSourceReferencesSIGUSR1, reason)
	}
}

func TestSourceScanRefusal_CleanApp(t *testing.T) {
	cmd := startNodeApp(t, `setTimeout(() => {}, 600000);`)

	if reason := sourceScanRefusal(cmd.Process.Pid); reason != "" {
		t.Errorf("expected no refusal for a clean application, got %q", reason)
	}
}

func TestSourceScanRefusal_EvaluatedHandlerIsDetected(t *testing.T) {
	cmd := startNodeScript(t, `
		process.on('SIGUSR1', () => console.log('reload'));
		setTimeout(() => {}, 600000);
	`)

	if reason := sourceScanRefusal(cmd.Process.Pid); reason != refusalSourceReferencesSIGUSR1 {
		t.Errorf("expected %q for a handler registered in --eval code, got %q", refusalSourceReferencesSIGUSR1, reason)
	}
}

func TestSourceScanRefusal_EvaluatedCleanScript(t *testing.T) {
	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)

	if reason := sourceScanRefusal(cmd.Process.Pid); reason != "" {
		t.Errorf("expected no refusal for clean --eval code, got %q", reason)
	}
}

func TestSIGUSR1Refusal_CleanAppIsSignalled(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/mem")
	}

	cmd := startNodeApp(t, `setTimeout(() => {}, 600000);`)

	if reason := sigusr1Refusal(cmd.Process.Pid, openNodeELF(t, cmd.Process.Pid)); reason != "" {
		t.Errorf("expected a clean Node application to be signaled, got %q", reason)
	}
}

func TestSIGUSR1Refusal_NoHandler(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/mem")
	}

	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)

	reason := sigusr1Refusal(cmd.Process.Pid, openNodeELF(t, cmd.Process.Pid))
	if reason != "" {
		t.Errorf("expected no refusal, got %q", reason)
	}
}

func TestSIGUSR1Refusal_WithHandler(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/mem")
	}

	cmd := startNodeScript(t, `
		process.on('SIGUSR1', () => console.log('got sigusr1'));
		setTimeout(() => {}, 600000);
	`)

	// An unstripped runtime is caught by the libuv signal tree; a stripped
	// distribution build falls back to the source scan. Either way the
	// handler must prevent the signal.
	reason := sigusr1Refusal(cmd.Process.Pid, openNodeELF(t, cmd.Process.Pid))
	if reason != refusalHandlerFound && reason != refusalSourceReferencesSIGUSR1 {
		t.Errorf("expected a refusal for a process with a custom SIGUSR1 handler, got %q", reason)
	}
}
