// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"context"
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
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
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

// startNodeScript evaluates code with "node -e". The working directory is a
// fresh temp dir, because the source scan falls back to it when the command
// line names no entry point.
func startNodeScript(t *testing.T, script string) *exec.Cmd {
	t.Helper()
	// Skips when node is absent, so `make test` on a host without it does not
	// fail. Every spawn helper guards here rather than at each call site.
	findNodeBinary(t)

	cmd := exec.Command("node", "-e", script)
	cmd.Dir = t.TempDir()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start node: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	awaitNodeReady(t, cmd.Process.Pid)
	return cmd
}

// startNodeApp runs a script from a file so the process has a resolvable
// application directory, which "node -e" does not.
func startNodeApp(t *testing.T, script string) *exec.Cmd {
	t.Helper()
	findNodeBinary(t)

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
	awaitNodeReady(t, cmd.Process.Pid)
	return cmd
}

// awaitNodeReady waits until the runtime has installed its own SIGUSR1
// handler, which is the point from which these tests can read anything
// meaningful about it. Polling rather than sleeping a fixed interval: the
// install lands milliseconds after exec, but that is a property of the runtime
// and not something to time.
//
// A runtime that never catches SIGUSR1 — built or launched to leave it alone —
// is an environment these tests cannot assert against, the same as one with no
// Node installed at all, so they skip rather than fail. The gates are exercised
// without a Node runtime elsewhere in this file. The kernel's own view goes
// into the message, because "fatal" alone does not say whether the process was
// alive and leaving the signal at its default or already gone.
func awaitNodeReady(t *testing.T, pid int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for sigusr1Disposition(pid) != signalDispositionHandled {
		if time.Now().After(deadline) {
			t.Skipf("this Node does not catch SIGUSR1, so there is nothing to assert against: %s",
				procSignalState(pid))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// awaitScriptHandler waits for a handler the script registered with
// process.on to reach libuv's signal tree.
//
// This is a later and separate event from the one awaitNodeReady waits for.
// Node's own SIGUSR1 handler is installed during bootstrap, before user code
// runs, and shows up in SigCgt; process.on goes through uv_signal_start and
// lands in the tree only once the script has executed. A test that reads the
// tree has to wait for this one.
func awaitScriptHandler(t *testing.T, pid int, elfFile *elf.File) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for hasUserSIGUSR1Handler(pid, elfFile, readNodeSymbols(elfFile)) != signalCheckFound {
		if time.Now().After(deadline) {
			t.Fatalf("the script's SIGUSR1 handler never reached libuv's signal tree")
		}
		time.Sleep(10 * time.Millisecond)
	}
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

	result := hasUserSIGUSR1Handler(cmd.Process.Pid, ef, readNodeSymbols(ef))
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
	awaitScriptHandler(t, cmd.Process.Pid, ef)

	result := hasUserSIGUSR1Handler(cmd.Process.Pid, ef, readNodeSymbols(ef))
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

	result := hasUserSIGUSR1Handler(cmd.Process.Pid, ef, readNodeSymbols(ef))
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
	if isNodeRuntime(os.Getpid(), readNodeSymbols(nil)) {
		t.Error("expected a nil ELF not to be identified as a Node.js runtime")
	}
}

func TestIsNodeRuntime_NodeBinary(t *testing.T) {
	if !isNodeRuntime(os.Getpid(), readNodeSymbols(openELFPath(t, findNodeBinary(t)))) {
		t.Error("expected the node binary to be identified as a Node.js runtime")
	}
}

func TestIsNodeRuntime_NonNodeExecutable(t *testing.T) {
	if isNodeRuntime(os.Getpid(), readNodeSymbols(testBinaryELF(t))) {
		t.Error("expected a non-Node executable not to be identified as a Node.js runtime")
	}
}

// The gate is fail-closed: an executable whose symbols say nothing loses
// injection unless the process maps libnode.so. A distribution build stripped
// to .dynsym is exactly that case, so the decision is asserted directly rather
// than only through whichever node happens to be installed.
func TestIsNodeRuntime_SymbolDecision(t *testing.T) {
	nodeELF := openELFPath(t, findNodeBinary(t))

	for _, tc := range []struct {
		name string
		syms nodeSymbols
		want bool
	}{
		{name: "runtime symbols present", syms: readNodeSymbols(nodeELF), want: true},
		// A stripped executable names nothing, so identification falls to the
		// mapped-library check, which this process fails.
		{name: "stripped executable", syms: nodeSymbols{}},
		// The signal tree is read separately; naming it does not identify a
		// runtime on its own, and only `identified` decides this gate.
		{name: "signal tree without identification", syms: nodeSymbols{hasTree: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A PID that maps no libnode.so isolates the symbol decision from
			// the mapped-library fallback.
			if got := isNodeRuntime(os.Getpid(), tc.syms); got != tc.want {
				t.Errorf("isNodeRuntime = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReadNodeSymbols_AbsentTable(t *testing.T) {
	syms := readNodeSymbols(nil)
	if syms.identified {
		t.Error("an absent symbol table must not identify a runtime")
	}
	if syms.hasTree {
		t.Error("an absent symbol table must not yield a signal tree")
	}
}

func TestHasMappedNodeLibrary_NonNodeProcess(t *testing.T) {
	if hasMappedNodeLibrary(os.Getpid()) {
		t.Error("expected no libnode.so mapping in a non-Node process")
	}
}

// procSignalState reports what the kernel says about a process, so a failure
// here does not need a second run to interpret: a zombie and a live process
// that never installed a handler both read as fatal otherwise.
func procSignalState(pid int) string {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return fmt.Sprintf("/proc/%d/status unreadable: %v", pid, err)
	}

	var fields []string
	for line := range strings.SplitSeq(string(status), "\n") {
		for _, prefix := range []string{"State:", "SigIgn:", "SigCgt:"} {
			if strings.HasPrefix(line, prefix) {
				fields = append(fields, strings.TrimSpace(line))
			}
		}
	}

	return strings.Join(fields, " ")
}

// The premise the disposition gate rests on: a Node runtime catches SIGUSR1,
// so the signal cannot terminate it. The spawn helper waits for exactly that,
// and this states it as an assertion rather than an implicit precondition.
func TestSigusr1Disposition_NodeCatchesSignal(t *testing.T) {
	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)

	if got := sigusr1Disposition(cmd.Process.Pid); got != signalDispositionHandled {
		t.Errorf("expected signalDispositionHandled for a Node process, got %d (%s)",
			got, procSignalState(cmd.Process.Pid))
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

// The wait exists for the window after exec in which a runtime has not yet
// installed its handler. A shell starts with SIGUSR1 fatal and takes the signal
// over partway through the window, so one PID's disposition flips and only a
// poll can observe it: reading once would answer fatal.
//
// A shell rather than a Node runtime, because the flip has to land inside the
// window on a loaded machine and a V8 startup is not something to bet that on.
func TestAwaitSignalDisposition_WaitsForHandlerInstall(t *testing.T) {
	cmd := exec.Command("sh", "-c", `sleep 0.1; trap "" USR1; sleep 60`)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start the shell: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	if got := awaitSignalDisposition(t.Context(), cmd.Process.Pid); got != signalDispositionHandled {
		t.Errorf("expected the wait to see the signal taken over, got %d (%s)",
			got, procSignalState(cmd.Process.Pid))
	}
}

// A process that never installs a handler is reported fatal once the window
// closes, rather than waited on forever.
func TestAwaitSignalDisposition_FatalAfterWindow(t *testing.T) {
	cmd := exec.Command("sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	start := time.Now()
	got := awaitSignalDisposition(t.Context(), cmd.Process.Pid)
	if got != signalDispositionFatal {
		t.Errorf("expected signalDispositionFatal, got %d", got)
	}
	if waited := time.Since(start); waited < dispositionWait {
		t.Errorf("returned after %v, want at least the %v window", waited, dispositionWait)
	}
}

// Shutdown concludes nothing about the target, so it must not be reported as
// the signal being fatal to it.
func TestAwaitSignalDisposition_CancellationIsUnknown(t *testing.T) {
	cmd := exec.Command("sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := awaitSignalDisposition(ctx, cmd.Process.Pid); got != signalDispositionUnknown {
		t.Errorf("expected signalDispositionUnknown on cancellation, got %d", got)
	}
}

func TestSigusr1Disposition_UnknownForDeadProcess(t *testing.T) {
	if got := sigusr1Disposition(unusedPID(t)); got != signalDispositionUnknown {
		t.Errorf("expected signalDispositionUnknown for a nonexistent pid, got %d", got)
	}
}

func TestSignalTreeRuntimeAddr_ResolvesForNode(t *testing.T) {
	cmd := startNodeScript(t, `setTimeout(() => {}, 600000);`)
	nodeELF := openNodeELF(t, cmd.Process.Pid)
	syms := readNodeSymbols(nodeELF)
	if !syms.hasTree {
		t.Skip("this node build names no uv__signal_tree; distribution builds strip it")
	}

	addr, ok := signalTreeRuntimeAddr(cmd.Process.Pid, nodeELF, syms)
	if !ok {
		t.Fatal("expected a named uv__signal_tree to resolve to a runtime address")
	}
	if addr == 0 {
		t.Error("expected a non-zero runtime address")
	}
}

func TestSIGUSR1Refusal_NonNodeExecutable(t *testing.T) {
	reason := sigusr1Refusal(context.Background(), os.Getpid(), testBinaryELF(t))
	if reason != refusalNotNodeRuntime {
		t.Errorf("expected %q, got %q", refusalNotNodeRuntime, reason)
	}
}

func TestSIGUSR1Refusal_NilELF(t *testing.T) {
	reason := sigusr1Refusal(context.Background(), os.Getpid(), nil)
	if reason != refusalNotNodeRuntime {
		t.Errorf("expected %q, got %q", refusalNotNodeRuntime, reason)
	}
}

func TestSIGUSR1Refusal_DispositionUnreadable(t *testing.T) {
	reason := sigusr1Refusal(context.Background(), unusedPID(t), openELFPath(t, findNodeBinary(t)))
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

	reason := sigusr1Refusal(context.Background(), cmd.Process.Pid, openELFPath(t, findNodeBinary(t)))
	if reason != refusalSignalIsFatal {
		t.Errorf("expected %q, got %q", refusalSignalIsFatal, reason)
	}
}

func TestSIGUSR1Refusal_CleanAppIsSignalled(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to read /proc/<pid>/mem")
	}

	cmd := startNodeApp(t, `setTimeout(() => {}, 600000);`)

	if reason := sigusr1Refusal(context.Background(), cmd.Process.Pid, openNodeELF(t, cmd.Process.Pid)); reason != "" {
		t.Errorf("expected a clean Node application to be signaled, got %q", reason)
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
	nodeELF := openNodeELF(t, cmd.Process.Pid)
	if _, ok := signalTreeRuntimeAddr(cmd.Process.Pid, nodeELF, readNodeSymbols(nodeELF)); !ok {
		t.Skip("this node build carries no readable libuv signal tree")
	}
	awaitScriptHandler(t, cmd.Process.Pid, nodeELF)

	reason := sigusr1Refusal(context.Background(), cmd.Process.Pid, nodeELF)
	if reason != refusalHandlerFound {
		t.Errorf("expected %q for a process with a custom SIGUSR1 handler, got %q", refusalHandlerFound, reason)
	}
}

// The gates decide whether the signal is sent at all. Without this, inverting
// the refusal check or moving the send above it leaves every other test green
// while OBI resumes killing what it cannot identify.
func TestAttachAgent_RefusalWithholdsTheSignal(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to enter the target's network namespace")
	}

	sent := 0
	restore := sendSIGUSR1
	sendSIGUSR1 = func(*procs.ProcessHandle) error {
		sent++
		return nil
	}
	t.Cleanup(func() { sendSIGUSR1 = restore })

	// Not a Node.js runtime, so the first gate refuses it.
	cmd := exec.Command("sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pid := app.PID(cmd.Process.Pid)
	startTime, err := procs.StartTime(pid)
	if err != nil {
		t.Fatalf("start time: %v", err)
	}
	handle, err := procs.OpenProcessHandle(pid, startTime)
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.TracePrinter = debug.TracePrinterText
	injector := NewNodeInjector(&cfg)

	target := InjectionTarget{Pid: pid, Process: handle}
	err = injector.attachAgent(context.Background(), target, testBinaryELF(t))

	// Asserted before the error, so that a regression here reports the signal
	// rather than whatever the injection went on to fail at afterwards.
	if sent != 0 {
		t.Fatalf("SIGUSR1 was sent %d times to a process the gates refused", sent)
	}
	if err != nil {
		t.Fatalf("attachAgent returned an error: %v", err)
	}
}
