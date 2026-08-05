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
	"github.com/prometheus/procfs"
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

const (
	testStaticTraceparent    = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86"
	testDuplicateTraceparent = "00-2122232425262728292a2b2c2d2e2f30-3132333435363738-01"
	testInvalidTraceparent   = "00-00000000000000000000000000000000-1112131415161718-01"
)

type traceparentWireResult struct {
	values []string
}

// TestHTTP1ClientTraceparentAuthority attaches the real eBPF gotracer to a live
// Go process and verifies both the HTTP/1 wire field and the emitted client span.
func TestHTTP1ClientTraceparentAuthority(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	if !ebpfcommon.SupportsContextPropagationWithProbe(slog.Default()) {
		t.Skip("kernel does not support bpf_probe_write_user context propagation (e.g. lockdown); skipping")
	}

	targetBin := buildHTTPClientTarget(t)
	send, spans := startHTTPClientTarget(t, targetBin)

	// Readiness: instead of a fixed sleep, poll until OBI's injection is
	// effective. NO_TP returns one value only once the uprobe is attached and
	// injecting, so this doubles as the "OBI still injects" assertion and
	// guarantees the probe is live before the authority checks below.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, strings.HasPrefix(send(t, "NO_TP"), "1|"),
			"OBI must inject a traceparent when the client didn't write one")
	}, 20*time.Second, 200*time.Millisecond)

	valid := parseTraceparentWireResult(t, send(t, "VALID_TP"))
	require.Equal(t,
		[]string{testStaticTraceparent},
		valid.values,
		"valid application field must suppress both direct and stale-map fallback injection")
	assertSpanTraceparent(t, waitForHTTPClientSpan(t, spans, "/valid-tp"), testStaticTraceparent)

	tls := parseTraceparentWireResult(t, send(t, "VALID_TLS_TP"))
	require.Equal(t, []string{testStaticTraceparent}, tls.values)
	assertSpanTraceparent(
		t, waitForHTTPClientSpan(t, spans, "/valid-tls-tp"), testStaticTraceparent,
	)

	duplicate := parseTraceparentWireResult(t, send(t, "DUPLICATE_TP"))
	require.Equal(t,
		[]string{testStaticTraceparent, testDuplicateTraceparent},
		duplicate.values,
		"application duplicate fields must remain unchanged without OBI injection")
	assertGeneratedSpanTraceparent(
		t,
		waitForHTTPClientSpan(t, spans, "/duplicate-tp"),
		testStaticTraceparent,
		testDuplicateTraceparent,
	)

	invalidThenValid := parseTraceparentWireResult(t, send(t, "INVALID_THEN_VALID_TP"))
	require.Equal(t,
		[]string{testInvalidTraceparent, testStaticTraceparent},
		invalidThenValid.values,
		"ambiguous application fields must remain unchanged without OBI injection")
	assertGeneratedSpanTraceparent(
		t,
		waitForHTTPClientSpan(t, spans, "/invalid-then-valid-tp"),
		testStaticTraceparent,
	)

	invalid := parseTraceparentWireResult(t, send(t, "INVALID_TP"))
	require.Equal(t,
		[]string{testInvalidTraceparent},
		invalid.values,
		"invalid application field must remain unchanged without OBI injection")
	assertGeneratedSpanTraceparent(t, waitForHTTPClientSpan(t, spans, "/invalid-tp"))
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

// startHTTPClientTarget starts the target, attaches the gotracer, and returns
// both a command function and the emitted-span stream.
func startHTTPClientTarget(
	t *testing.T,
	bin string,
) (func(t *testing.T, mode string) string, <-chan []request.Span) {
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

	spans := attachGoTracer(t, app.PID(cmd.Process.Pid))

	send := func(t *testing.T, mode string) string {
		t.Helper()
		_, err := io.WriteString(stdin, mode+"\n")
		require.NoError(t, err)
		line := waitForClientLine(t, stdoutLines, "TP_RESULT=", 30*time.Second)
		return strings.TrimPrefix(strings.TrimSpace(line), "TP_RESULT=")
	}
	return send, spans
}

// attachGoTracer wires up the real ProcessTracer with the gotracer against the
// given PID, mirroring the production discovery/attach path.
func attachGoTracer(t *testing.T, pid app.PID) <-chan []request.Span {
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

	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1000))
	received := spans.Subscribe(msg.SubscriberName("tphttp-test"))
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
	return received
}

func parseTraceparentWireResult(t *testing.T, result string) traceparentWireResult {
	t.Helper()
	countAndValues := strings.SplitN(result, "|", 2)
	require.Len(t, countAndValues, 2, "malformed target result %q", result)
	count, err := strconv.Atoi(countAndValues[0])
	require.NoError(t, err)

	var values []string
	if countAndValues[1] != "" {
		values = strings.Split(countAndValues[1], ",")
	}
	require.Len(t, values, count, "target traceparent count did not match its values")
	return traceparentWireResult{values: values}
}

func validVersion00Traceparent(value string) bool {
	if len(value) != 55 || !strings.HasPrefix(value, "00-") ||
		value[35] != '-' || value[52] != '-' {
		return false
	}
	for _, field := range []string{value[3:35], value[36:52], value[53:55]} {
		for i := range len(field) {
			if !strings.ContainsRune("0123456789abcdef", rune(field[i])) {
				return false
			}
		}
	}
	return value[3:35] != strings.Repeat("0", 32) &&
		value[36:52] != strings.Repeat("0", 16)
}

func assertSpanTraceparent(t *testing.T, span request.Span, traceparent string) {
	t.Helper()
	require.True(t, validVersion00Traceparent(traceparent))
	assert.Equal(t, traceparent[3:35], span.TraceID.String(), "client span trace ID")
	assert.Equal(t, traceparent[36:52], span.SpanID.String(), "client span ID")
	flags, err := strconv.ParseUint(traceparent[53:55], 16, 8)
	require.NoError(t, err)
	assert.Equal(t, uint8(flags), span.TraceFlags, "client span trace flags")
	assert.True(t, span.BPFDecision, "application wire flags must be an authoritative BPF decision")
	assert.False(t, span.ParentSpanID.IsValid(), "application traceparent adoption clears parent ID")
}

func assertGeneratedSpanTraceparent(
	t *testing.T,
	span request.Span,
	rejectedTraceparents ...string,
) {
	t.Helper()
	require.True(t, span.TraceID.IsValid(), "generated client trace ID")
	require.True(t, span.SpanID.IsValid(), "generated client span ID")
	assert.True(t, span.BPFDecision, "generated context must carry an authoritative BPF decision")
	assert.False(t, span.ParentSpanID.IsValid(), "generated client context must be a root span")

	spanContext := span.TraceID.String() + "-" + span.SpanID.String()
	for _, traceparent := range rejectedTraceparents {
		require.True(t, validVersion00Traceparent(traceparent))
		assert.NotEqual(
			t,
			traceparent[3:52],
			spanContext,
			"non-authoritative application traceparent must not be adopted",
		)
	}
}

func waitForHTTPClientSpan(
	t *testing.T,
	spans <-chan []request.Span,
	path string,
) request.Span {
	t.Helper()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case batch, ok := <-spans:
			require.True(t, ok, "span stream closed while waiting for HTTP client path %q", path)
			for _, span := range batch {
				if span.Type == request.EventTypeHTTPClient && span.Path == path {
					return span
				}
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for HTTP client span path %q", path)
		}
	}
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

	proc, err := procfs.NewProc(int(pid))
	require.NoError(t, err)
	procStat, err := proc.Stat()
	require.NoError(t, err)
	const nanosecondsPerClockTick = uint64(time.Second) / 100
	startTime := procStat.Starttime * nanosecondsPerClockTick
	require.NotZero(t, startTime)

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
		StartTime:      startTime,
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
