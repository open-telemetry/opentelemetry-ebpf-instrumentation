// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"context"
	"io"
	"log/slog"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestGRPCClientTraceparentAuthorityOldTLS(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())
	if !ebpfcommon.SupportsContextPropagationWithProbe(slog.Default()) {
		t.Skip("kernel does not support bpf_probe_write_user context propagation")
	}

	targetBin := buildGRPCClientTarget(t)
	send, spans := startGRPCClientTarget(t, targetBin)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		result := parseTraceparentWireResult(t, send(t, "NO_TP"))
		assert.Len(c, result.values, 1)
		if len(result.values) == 1 {
			assert.True(c, validVersion00Traceparent(result.values[0]))
		}
	}, 20*time.Second, 200*time.Millisecond)

	oversized := parseTraceparentWireResult(t, send(t, "LARGE_NO_TP"))
	require.Empty(t, oversized.values)

	generated := parseTraceparentWireResult(t, send(t, "NO_TP"))
	require.Len(t, generated.values, 1)
	require.True(t, validVersion00Traceparent(generated.values[0]))
	assertSpanTraceparent(
		t,
		waitForGRPCClientSpanTraceparent(t, spans, generated.values[0]),
		generated.values[0],
	)

	application := parseTraceparentWireResult(t, send(t, "VALID_TP"))
	require.Equal(t, []string{testStaticTraceparent}, application.values)
	assertSpanTraceparent(
		t,
		waitForGRPCClientSpanTraceparent(t, spans, testStaticTraceparent),
		testStaticTraceparent,
	)
}

func buildGRPCClientTarget(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "tpgrpcclient")
	cmd := osexec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join("testdata", "tpgrpcclient")
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build tpgrpcclient:\n%s", string(out))
	return bin
}

func startGRPCClientTarget(
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

	stdoutLines := collectClientLines(t, "gRPC target stdout", stdout)
	_ = collectClientLines(t, "gRPC target stderr", stderr)
	waitForClientLine(t, stdoutLines, "READY", 30*time.Second)

	assertOldGRPCWriterBufferOffset(t, app.PID(cmd.Process.Pid))
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

func assertOldGRPCWriterBufferOffset(t *testing.T, pid app.PID) {
	t.Helper()

	cfg := obi.DefaultConfig
	cfg.EBPF.ContextPropagation = config.ContextPropagationAll
	fileInfo := goProcessFileInfo(t, pid)
	offsets, err := goexec.InspectOffsets(fileInfo, goFunctionNames(&cfg))
	require.NoError(t, err)
	require.Contains(t, offsets.Field, goexec.GrpcTransportBufWriterBufPos)
	assert.Zero(t, offsets.Field[goexec.GrpcTransportBufWriterBufPos],
		"grpc-go 1.56 bufWriter.buf must exercise the valid zero-offset path")
}

func waitForGRPCClientSpanTraceparent(
	t *testing.T,
	spans <-chan []request.Span,
	traceparent string,
) request.Span {
	t.Helper()
	require.True(t, validVersion00Traceparent(traceparent))
	wantTraceID := traceparent[3:35]
	wantSpanID := traceparent[36:52]

	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case batch, ok := <-spans:
			require.True(t, ok, "span stream closed while waiting for gRPC client traceparent")
			for _, span := range batch {
				if span.Type == request.EventTypeGRPCClient &&
					span.TraceID.String() == wantTraceID &&
					span.SpanID.String() == wantSpanID {
					return span
				}
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for gRPC client traceparent %q", traceparent)
		}
	}
}
