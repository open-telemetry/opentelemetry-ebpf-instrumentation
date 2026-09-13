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
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type spanCollector struct {
	mu    sync.Mutex
	spans []request.Span
}

func (sc *spanCollector) add(batch []request.Span) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.spans = append(sc.spans, batch...)
}

func (sc *spanCollector) getSpans() []request.Span {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	copied := make([]request.Span, len(sc.spans))
	copy(copied, sc.spans)
	return copied
}

func (sc *spanCollector) clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.spans = nil
}

func (sc *spanCollector) getGRPCClientSpans() []request.Span {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	var res []request.Span
	for _, s := range sc.spans {
		if s.Type == request.EventTypeGRPCClient {
			res = append(res, s)
		}
	}
	return res
}

func buildGRPCNestedClientTarget(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "grpcclient_nested")
	cmd := osexec.Command("go", "build", "-buildvcs=false", "-o", bin, "testdata/grpcclient_nested/main.go")
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build grpcclient_nested:\n%s", string(out))
	return bin
}

func startGRPCNestedClientTarget(t *testing.T, bin string) (func(string) string, *spanCollector) {
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

	stdoutLines := collectClientLines(t, "target stdout", stdout)
	_ = collectClientLines(t, "target stderr", stderr)
	waitForClientLine(t, stdoutLines, "READY", 30*time.Second)

	cfg := obi.DefaultConfig
	cfg.LogLevel = obi.LogLevelDebug
	cfg.EBPF.BpfDebug = true
	cfg.EBPF.ContextPropagation = config.ContextPropagationHeaders

	pidsFilter := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.With("component", "grpc-nested-pids"), imetrics.NoopReporter{})
	goTracer := New(pidsFilter, &cfg, imetrics.NoopReporter{})
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = pidsFilter

	processTracer := ebpftracer.NewProcessTracer(ebpftracer.Go, []ebpftracer.Tracer{goTracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, processTracer.Init(eventContext, &cfg))

	pid := app.PID(cmd.Process.Pid)
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

	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(50))
	collector := &spanCollector{}
	spansCh := spans.Subscribe(msg.SubscriberName("test-collector"))

	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for batch := range spansCh {
			collector.add(batch)
		}
	}()

	runCtx, runCancel := context.WithCancel(context.Background())
	tracerDone := make(chan struct{})
	go func() {
		defer close(tracerDone)
		processTracer.Run(runCtx, eventContext, spans)
	}()

	t.Cleanup(func() {
		_, _ = io.WriteString(stdin, "EXIT\n")
		cancel()
		_ = cmd.Wait()

		runCancel()
		select {
		case <-tracerDone:
		case <-time.After(cfg.ShutdownTimeout):
			t.Error("timed out waiting for gotracer ProcessTracer to stop")
		}
		spans.Close()
		<-collectorDone
	})

	send := func(cmd string) string {
		_, err := io.WriteString(stdin, cmd+"\n")
		require.NoError(t, err)
		line := waitForClientLine(t, stdoutLines, "CMD="+cmd, 30*time.Second)
		return line
	}

	return send, collector
}

func TestGRPCClientNestedInvocations(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	targetBin := buildGRPCNestedClientTarget(t)
	send, collector := startGRPCNestedClientTarget(t, targetBin)

	// 1. Unary call
	t.Run("unary_baseline", func(t *testing.T) {
		collector.clear()
		res := send("UNARY")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.NotEmpty(c, grpcSpans)
			if len(grpcSpans) > 0 {
				assert.Equal(c, "/TestService/Unary", grpcSpans[0].Path)
				assert.Equal(c, 0, grpcSpans[0].Status)
			}
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 2. Nested unary on same ClientConn (A.Invoke -> interceptor -> A.Invoke)
	t.Run("nested_same_connection", func(t *testing.T) {
		collector.clear()
		res := send("NESTED_SAME_CONN")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.GreaterOrEqual(c, len(grpcSpans), 2, "both inner and outer spans should be emitted")
		}, 10*time.Second, 100*time.Millisecond)

		spans := collector.getGRPCClientSpans()
		for _, s := range spans {
			assert.Equal(t, "/TestService/Unary", s.Path)
			assert.Equal(t, 0, s.Status)
		}
	})

	// 3. Nested unary on different ClientConn (A.Invoke -> interceptor -> B.Invoke)
	t.Run("nested_diff_connection", func(t *testing.T) {
		collector.clear()
		res := send("NESTED_DIFF_CONN")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.GreaterOrEqual(c, len(grpcSpans), 2, "both inner and outer spans should be emitted")
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 4. Recursive unary (depth 3)
	t.Run("recursive_unary", func(t *testing.T) {
		collector.clear()
		res := send("RECURSIVE_UNARY")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.GreaterOrEqual(c, len(grpcSpans), 3, "all 3 recursive spans should be emitted")
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 5. Stack overflow (> 4)
	t.Run("stack_overflow", func(t *testing.T) {
		collector.clear()
		res := send("STACK_OVERFLOW")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			// Up to 4 tracked frames should emit spans, and no crash/corruption
			assert.GreaterOrEqual(c, len(grpcSpans), 4)
		}, 10*time.Second, 100*time.Millisecond)
	})
}

func TestGRPCClientStreamLifecycleRaces(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	targetBin := buildGRPCNestedClientTarget(t)
	send, collector := startGRPCNestedClientTarget(t, targetBin)

	// 1. Normal streaming RPC
	t.Run("stream_normal", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_NORMAL")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.NotEmpty(c, streamSpans, "stream span should be emitted upon finish")
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 2. Race: context already cancelled prior to NewStream
	t.Run("stream_race_already_cancelled", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_RACE_ALREADY_CANCELLED")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			t.Logf("already_cancelled spans count: %d", len(grpcSpans))
			for _, s := range grpcSpans {
				t.Logf("already_cancelled span: path=%s status=%d", s.Path, s.Status)
			}
			assert.NotEmpty(c, grpcSpans, "span should be emitted for cancelled stream")
		}, 5*time.Second, 100*time.Millisecond)
	})

	// 3. Race: context cancelled quickly / concurrently during stream creation
	t.Run("stream_race_quickly_cancelled", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_RACE_QUICKLY_CANCELLED")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			t.Logf("quickly_cancelled spans count: %d", len(grpcSpans))
			assert.NotEmpty(c, grpcSpans, "spans should be emitted for quickly cancelled streams")
		}, 5*time.Second, 100*time.Millisecond)
	})

	// 4. Race: concurrent ClientConn.Close during NewStream
	t.Run("stream_race_concurrent_close", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_RACE_CONCURRENT_CLOSE")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			t.Logf("concurrent_close spans count: %d", len(grpcSpans))
			assert.NotEmpty(c, grpcSpans, "spans should be emitted despite concurrent close")
		}, 5*time.Second, 100*time.Millisecond)
	})
}
