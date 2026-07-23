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

// TestHTTP1ClientTraceparentNotDuplicated attaches the eBPF gotracer to a live Go process that
// issues an HTTP/1 request to its own loopback server, and checks how many
// `Traceparent` header values reach the receiver:
//
//   - WITH_TP: the client already wrote its own traceparent, so OBI must skip
//     injection -> exactly ONE arrives (before the fix this was TWO).
//   - NO_TP: no traceparent present, so OBI injects -> exactly ONE arrives,
//     proving injection still happens when the header is absent.
func TestHTTP1ClientTraceparentNotDuplicated(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	if !ebpfcommon.SupportsContextPropagationWithProbe(slog.Default()) {
		t.Skip("kernel does not support bpf_probe_write_user context propagation (e.g. lockdown); skipping")
	}

	targetBin := buildHTTPClientTarget(t)
	send := startHTTPClientTarget(t, targetBin)

	// Readiness: instead of a fixed sleep, poll until OBI's injection is
	// effective. NO_TP returns "1" only once the uprobe is attached and
	// injecting, so this doubles as the "OBI still injects" assertion and
	// guarantees the probe is live before the no-duplicate check below.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "1", send(t, "NO_TP"),
			"OBI must inject a traceparent when the client didn't write one")
	}, 20*time.Second, 200*time.Millisecond)

	// With injection confirmed live, a client that already wrote its own
	// traceparent must not get a second one appended.
	assert.Equal(t, "1", send(t, "WITH_TP"),
		"OBI must not append a second traceparent when the client already wrote one")
}

// buildHTTPClientTarget compiles the self-contained helper binary. Its single
// source file carries a `//go:build ignore` tag, so it is named explicitly to
// bypass the constraint.
func buildHTTPClientTarget(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "tphttpclient")
	cmd := osexec.Command("go", "build", "-o", bin, "testdata/tphttpclient/main.go")
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build tphttpclient:\n%s", string(out))
	return bin
}

// startHTTPClientTarget starts the target, attaches the gotracer, and returns a
// send function that issues one request in the given mode ("WITH_TP"/"NO_TP")
// and returns the number of Traceparent headers the receiver reported. The
// target loops over stdin, so send can be called repeatedly (e.g. for polling).
func startHTTPClientTarget(t *testing.T, bin string) func(t *testing.T, mode string) string {
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

	stdoutLines := collectClientLines(t, "target stdout", stdout)
	_ = collectClientLines(t, "target stderr", stderr)
	waitForClientLine(t, stdoutLines, "READY", 30*time.Second)

	attachGoTracer(t, app.PID(cmd.Process.Pid))

	return func(t *testing.T, mode string) string {
		t.Helper()
		_, err := io.WriteString(stdin, mode+"\n")
		require.NoError(t, err)
		line := waitForClientLine(t, stdoutLines, "TP_COUNT=", 30*time.Second)
		return strings.TrimPrefix(strings.TrimSpace(line), "TP_COUNT=")
	}
}

// attachGoTracer wires up the real ProcessTracer with the gotracer against the
// given PID, mirroring the production discovery/attach path.
func attachGoTracer(t *testing.T, pid app.PID) {
	t.Helper()

	cfg := obi.DefaultConfig
	cfg.LogLevel = obi.LogLevelDebug
	cfg.EBPF.BpfDebug = true
	cfg.EBPF.ContextPropagation = config.ContextPropagationAll

	pidsFilter := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.With("component", "tphttp-pids"), imetrics.NoopReporter{})
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
	// so it must be opened and attached to the FileInfo, like the real typer.
	elfFile, err := elf.Open(procExeLinkPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = elfFile.Close() })

	return discexec.New(discexec.Init{
		Service: svc.Attrs{
			UID:         svc.UID{Name: "tphttp", Namespace: "integration-test"},
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

func collectClientLines(t *testing.T, name string, r io.Reader) <-chan string {
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
		// Surface read errors (broken pipe/truncation) so failures show up as a
		// diagnosable log line rather than an opaque waitForClientLine timeout.
		if err := scanner.Err(); err != nil {
			t.Logf("%s scanner error: %v", name, err)
		}
	}()
	return lines
}

func waitForClientLine(t *testing.T, lines <-chan string, want string, timeout time.Duration) string {
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
