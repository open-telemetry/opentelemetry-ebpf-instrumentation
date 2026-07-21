// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"bufio"
	"context"
	"debug/elf"
	"io"
	"log/slog"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// TestGoSDKTraceparentNotDuplicated is the end-to-end regression test for
// GitHub issue #2732. It attaches the real gotracer to a live Go process that
// issues an HTTP/1 request already carrying its own `traceparent`, and checks
// how many `Traceparent` header values reach the loopback receiver:
//
//   - SDK mode (the fix): the request runs under an OTel SDK span, so OBI's
//     in-kernel SDK-delegate detection marks the process and skips its uprobe
//     injection — exactly ONE traceparent arrives.
//   - PLAIN mode (control): the process writes its own traceparent without ever
//     touching the SDK, so OBI does not detect it and injects as usual — TWO
//     arrive. This proves the injection path is active and the test can observe
//     a duplicate, so the SDK-mode "1" is meaningful and not a false pass.
func TestGoSDKTraceparentNotDuplicated(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	if !ebpfcommon.SupportsContextPropagationWithProbe(slog.Default()) {
		t.Skip("kernel does not support bpf_probe_write_user context propagation (e.g. lockdown); skipping")
	}

	targetBin := buildTraceparentTarget(t)

	t.Run("SDK-instrumented: no duplicate traceparent", func(t *testing.T) {
		got := runTraceparentTarget(t, targetBin, "SDK")
		assert.Equal(t, "1", got,
			"with the SDK detected, OBI must not append a second traceparent")
	})

	t.Run("non-SDK control: OBI injects", func(t *testing.T) {
		got := runTraceparentTarget(t, targetBin, "PLAIN")
		assert.Equal(t, "2", got,
			"a process not detected as SDK-instrumented still gets OBI's traceparent injected")
	})
}

// buildTraceparentTarget compiles the self-contained SDK-instrumented helper
// binary (testdata/tpinjecttarget). Its single source file carries a
// `//go:build ignore` tag, so it is named explicitly to bypass the constraint.
func buildTraceparentTarget(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "tpinjecttarget")
	cmd := osexec.Command("go", "build", "-o", bin, "testdata/tpinjecttarget/main.go")
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build tpinjecttarget:\n%s", string(out))
	return bin
}

// runTraceparentTarget starts the target, attaches the gotracer, sends the
// given mode command ("SDK" or "PLAIN") and returns the number of Traceparent
// headers the receiver reported.
func runTraceparentTarget(t *testing.T, bin, mode string) string {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := osexec.CommandContext(ctx, bin)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_, _ = io.WriteString(stdin, "EXIT\n")
		cancel()
		_ = cmd.Wait()
	})

	stdoutLines := collectLines(t, "target stdout", stdout)
	_ = collectLines(t, "target stderr", stderr)
	waitForLine(t, stdoutLines, "READY", 30*time.Second)

	attachGoTracer(t, app.PID(cmd.Process.Pid))

	// Give the uprobes a moment to be effective before the first request.
	time.Sleep(500 * time.Millisecond)

	_, err = io.WriteString(stdin, mode+"\n")
	require.NoError(t, err)

	line := waitForLine(t, stdoutLines, "TP_COUNT=", 30*time.Second)
	return strings.TrimPrefix(strings.TrimSpace(line), "TP_COUNT=")
}

// attachGoTracer wires up the real ProcessTracer with the gotracer against the
// given PID, mirroring the production discovery/attach path.
func attachGoTracer(t *testing.T, pid app.PID) {
	t.Helper()

	cfg := obi.DefaultConfig
	cfg.LogLevel = obi.LogLevelDebug
	cfg.EBPF.BpfDebug = true
	cfg.EBPF.ContextPropagation = config.ContextPropagationAll

	pidsFilter := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.With("component", "tpinject-pids"), imetrics.NoopReporter{})
	goTracer := New(pidsFilter, &cfg, imetrics.NoopReporter{})
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = pidsFilter

	processTracer := ebpftracer.NewProcessTracer(ebpftracer.Go, []ebpftracer.Tracer{goTracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, processTracer.Init(eventContext, &cfg))

	fileInfo := goProcessFileInfo(t, pid)
	offsets, err := goexec.InspectOffsets(fileInfo, goFunctionNames(&cfg))
	require.NoError(t, err)

	processTracer.AllowPID(pid, fileInfo.Ns(), fileInfo)

	executable, err := link.OpenExecutable(fileInfo.ProExeLinkPath())
	require.NoError(t, err)
	require.NoError(t, processTracer.NewExecutable(executable, &ebpftracer.Instrumentable{
		Type:     svc.InstrumentableGolang,
		FileInfo: fileInfo,
		Offsets:  offsets,
	}))

	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		processTracer.Run(runCtx, eventContext, spans)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("timed out waiting for gotracer ProcessTracer to stop")
		}
		spans.Close()
	})
}

// goFunctionNames returns the union of Go symbols the gotracer probes, matching
// the discovery typer's loadAllGoFunctionNames so offset resolution succeeds.
func goFunctionNames(cfg *obi.Config) []string {
	uniq := map[string]struct{}{}
	var funcs []string
	add := func(sym string) {
		if _, ok := uniq[sym]; ok {
			return
		}
		uniq[sym] = struct{}{}
		funcs = append(funcs, sym)
	}

	tracer := New(nil, cfg, imetrics.NoopReporter{})
	for sym := range tracer.GoProbes() {
		add(sym)
	}
	for _, sym := range GoChannelLinkProbeSymbols() {
		add(sym)
	}
	for _, sym := range GoRuntimeMetricProbeSymbols() {
		add(sym)
	}
	return funcs
}

func goProcessFileInfo(t *testing.T, pid app.PID) *discexec.FileInfo {
	t.Helper()

	procExeLinkPath := "/proc/" + strconv.Itoa(int(pid)) + "/exe"
	cmdExePath, err := os.Readlink(procExeLinkPath)
	require.NoError(t, err)

	info, err := os.Stat(procExeLinkPath)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	ns, err := procs.FindNamespace(pid)
	require.NoError(t, err)

	// Go offset resolution (goexec.InspectOffsets) reads the executable's ELF,
	// so it must be opened and attached to the FileInfo, just like the real
	// discovery typer does.
	elfFile, err := elf.Open(procExeLinkPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = elfFile.Close() })

	return discexec.New(discexec.Init{
		Service: svc.Attrs{
			UID:         svc.UID{Name: "tpinject", Namespace: "integration-test"},
			SDKLanguage: svc.InstrumentableGolang,
		},
		ELF:            elfFile,
		CmdExePath:     cmdExePath,
		ProExeLinkPath: procExeLinkPath,
		Pid:            pid,
		Dev:            uint64(stat.Dev),
		Ino:            stat.Ino,
		Ns:             ns,
	})
}

func collectLines(t *testing.T, name string, r io.Reader) <-chan string {
	t.Helper()
	lines := make(chan string, 100)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("%s: %s", name, line)
			lines <- line
		}
	}()
	return lines
}

func waitForLine(t *testing.T, lines <-chan string, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			require.Truef(t, ok, "process output closed before %q", want)
			if strings.Contains(line, want) {
				return line
			}
		case <-deadline:
			t.Fatalf("timed out waiting for process line containing %q", want)
		}
	}
}
