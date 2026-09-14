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
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

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

func buildGRPCNestedClientTargetStripped(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "grpcclient_nested_stripped")
	cmd := osexec.Command("go", "build", "-buildvcs=false", "-ldflags", "-s -w", "-o", bin, "testdata/grpcclient_nested/main.go")
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build grpcclient_nested stripped:\n%s", string(out))
	return bin
}

func startGRPCNestedClientTarget(t *testing.T, bin string) (func(string) string, *spanCollector, *Tracer) {
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

	return send, collector, goTracer
}

func assertNoStaleStreams(t *testing.T, tr *Tracer) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var key BpfGoAddrKeyT
		var val BpfGrpcClientStreamStateT
		iter := tr.bpfObjects.OngoingGrpcClientStreams.Iterate()
		count := 0
		for iter.Next(&key, &val) {
			count++
			t.Logf("STALE ongoing_grpc_client_streams: pid=%d addr=%x", key.Pid, key.Addr)
		}
		assert.NoError(c, iter.Err())
		assert.Zero(c, count, "ongoing_grpc_client_streams should have no stale entries")

		var earlyVal BpfGrpcClientEarlyFinishT
		earlyIter := tr.bpfObjects.EarlyGrpcClientFinishes.Iterate()
		earlyCount := 0
		for earlyIter.Next(&key, &earlyVal) {
			earlyCount++
			t.Logf("STALE early_grpc_client_finishes: pid=%d addr=%x err=%d", key.Pid, key.Addr, earlyVal.HasErr)
		}
		assert.NoError(c, earlyIter.Err())
		assert.Zero(c, earlyCount, "early_grpc_client_finishes should have no stale entries")
	}, 5*time.Second, 100*time.Millisecond)
}

func TestGRPCClientNestedInvocations(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	targetBin := buildGRPCNestedClientTarget(t)
	send, collector, _ := startGRPCNestedClientTarget(t, targetBin)

	// 1. Unary call
	t.Run("unary_baseline", func(t *testing.T) {
		collector.clear()
		res := send("UNARY")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.Len(c, grpcSpans, 1)
			if len(grpcSpans) == 1 {
				assert.Equal(c, "/TestService/Unary", grpcSpans[0].Path)
				assert.Equal(c, 0, grpcSpans[0].Status)
				assert.True(c, grpcSpans[0].TraceID.IsValid())
				assert.True(c, grpcSpans[0].SpanID.IsValid())
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
			assert.Len(c, grpcSpans, 2, "exactly 2 spans should be emitted (inner and outer)")
			if len(grpcSpans) == 2 {
				sort.Slice(grpcSpans, func(i, j int) bool { return grpcSpans[i].Start < grpcSpans[j].Start })
				outer := grpcSpans[0]
				inner := grpcSpans[1]

				assert.Equal(c, "/TestService/Unary", inner.Path)
				assert.Equal(c, "/TestService/Unary", outer.Path)
				assert.Equal(c, 0, inner.Status)
				assert.Equal(c, 0, outer.Status)

				assert.True(c, inner.SpanID.IsValid())
				assert.True(c, outer.SpanID.IsValid())
				assert.NotEqual(c, inner.SpanID, outer.SpanID, "span IDs must be unique")
				assert.True(c, inner.TraceID.IsValid())
				assert.True(c, outer.TraceID.IsValid())
				t.Logf("nested_same_connection: outer TraceID=%s SpanID=%s ParentSpanID=%s", outer.TraceID, outer.SpanID, outer.ParentSpanID)
				t.Logf("nested_same_connection: inner TraceID=%s SpanID=%s ParentSpanID=%s", inner.TraceID, inner.SpanID, inner.ParentSpanID)
			}
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 3. Nested unary on different ClientConn (A.Invoke -> interceptor -> B.Invoke)
	t.Run("nested_diff_connection", func(t *testing.T) {
		collector.clear()
		res := send("NESTED_DIFF_CONN")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.Len(c, grpcSpans, 2, "exactly 2 spans should be emitted (inner on connB and outer on connA)")
			if len(grpcSpans) == 2 {
				sort.Slice(grpcSpans, func(i, j int) bool { return grpcSpans[i].Start < grpcSpans[j].Start })
				outer := grpcSpans[0]
				inner := grpcSpans[1]

				assert.Equal(c, "/TestService/Unary", inner.Path)
				assert.Equal(c, "/TestService/Unary", outer.Path)
				assert.Equal(c, 0, inner.Status)
				assert.Equal(c, 0, outer.Status)

				assert.True(c, inner.SpanID.IsValid())
				assert.True(c, outer.SpanID.IsValid())
				assert.NotEqual(c, inner.SpanID, outer.SpanID, "span IDs must be unique")
				assert.True(c, inner.TraceID.IsValid())
				assert.True(c, outer.TraceID.IsValid())
			}
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 4. Recursive unary (depth 3: depths 0, 1, 2)
	t.Run("recursive_unary", func(t *testing.T) {
		collector.clear()
		res := send("RECURSIVE_UNARY")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.Len(c, grpcSpans, 3, "all 3 recursive spans should be emitted")
			if len(grpcSpans) == 3 {
				sort.Slice(grpcSpans, func(i, j int) bool { return grpcSpans[i].Start < grpcSpans[j].Start })
				spanIDs := make(map[trace.SpanID]struct{})
				for i, s := range grpcSpans {
					assert.Equal(c, "/TestService/Unary", s.Path)
					assert.Equal(c, 0, s.Status)
					assert.True(c, s.SpanID.IsValid())
					assert.True(c, s.TraceID.IsValid())
					spanIDs[s.SpanID] = struct{}{}
					t.Logf("recursive_unary[%d]: TraceID=%s SpanID=%s ParentSpanID=%s", i, s.TraceID, s.SpanID, s.ParentSpanID)
				}
				assert.Len(c, spanIDs, 3, "all 3 spans must have unique span IDs")
			}
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 5. Stack overflow (> 4)
	t.Run("stack_overflow", func(t *testing.T) {
		collector.clear()
		res := send("STACK_OVERFLOW")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			assert.Len(c, grpcSpans, 4, "exactly 4 tracked spans should be emitted when stack capacity is 4")
			spanIDs := make(map[trace.SpanID]struct{})
			for _, s := range grpcSpans {
				assert.Equal(c, "/TestService/Unary", s.Path)
				assert.Equal(c, 0, s.Status)
				spanIDs[s.SpanID] = struct{}{}
			}
			assert.Len(c, spanIDs, 4, "all 4 tracked spans must have unique span IDs")
		}, 10*time.Second, 100*time.Millisecond)
	})
}

func TestGRPCClientStreamLifecycleRaces(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	targetBin := buildGRPCNestedClientTarget(t)
	send, collector, tracer := startGRPCNestedClientTarget(t, targetBin)

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
			assert.Len(c, streamSpans, 1, "stream span should be emitted upon finish")
			if len(streamSpans) == 1 {
				assert.Equal(c, "/TestService/Stream", streamSpans[0].Path)
				assert.Equal(c, 0, streamSpans[0].Status, "normally completed stream must have OK status")
				assert.True(c, streamSpans[0].TraceID.IsValid())
				assert.True(c, streamSpans[0].SpanID.IsValid())
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 1b. Regression: errors.New("EOF") must remain non-zero error status (unlike io.EOF)
	t.Run("stream_err_new_eof", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_ERR_NEW_EOF")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 1, "stream span should be emitted upon finish")
			if len(streamSpans) == 1 {
				assert.Equal(c, "/TestService/Stream", streamSpans[0].Path)
				assert.NotEqual(c, 0, streamSpans[0].Status, "errors.New(\"EOF\") must produce error status != 0")
				assert.True(c, streamSpans[0].TraceID.IsValid())
				assert.True(c, streamSpans[0].SpanID.IsValid())
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 2. Race: context already cancelled prior to NewStream
	t.Run("stream_race_already_cancelled", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_RACE_ALREADY_CANCELLED")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 1, "exactly 1 span should be emitted for cancelled stream")
			if len(streamSpans) == 1 {
				assert.Equal(c, "/TestService/Stream", streamSpans[0].Path)
				assert.NotZero(c, streamSpans[0].Status, "cancelled stream must have non-zero status")
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 3. Race: context cancelled quickly / concurrently during stream creation
	t.Run("stream_race_quickly_cancelled", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_RACE_QUICKLY_CANCELLED")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 5, "exactly 5 stream spans should be emitted for 5 quickly cancelled streams")
			for _, s := range streamSpans {
				assert.Equal(c, "/TestService/Stream", s.Path)
				assert.NotZero(c, s.Status, "cancelled stream should have non-zero status")
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 4. Race: concurrent ClientConn.Close during NewStream
	t.Run("stream_race_concurrent_close", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_RACE_CONCURRENT_CLOSE")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 5, "exactly 5 stream spans should be emitted despite concurrent close")
			for _, s := range streamSpans {
				assert.Equal(c, "/TestService/Stream", s.Path)
				assert.NotZero(c, s.Status, "closed stream should have non-zero status")
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 5. Race: stream finish before ClientConn.NewStream return
	t.Run("stream_race_finish_before_return", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_FINISH_BEFORE_RETURN")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 1, "exactly 1 stream span should be emitted for stream finished before return")
			if len(streamSpans) == 1 {
				assert.Equal(c, "/TestService/Stream", streamSpans[0].Path)
				assert.NotZero(c, streamSpans[0].Status)
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 6. Race: stream finish during publication (high repetition)
	t.Run("stream_race_finish_during_publication", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_FINISH_DURING_PUBLICATION")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 20, "exactly 20 stream spans should be emitted for 20 streams")
			for _, s := range streamSpans {
				assert.Equal(c, "/TestService/Stream", s.Path)
				assert.NotZero(c, s.Status)
			}
		}, 15*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 7. Race: concurrent multiple finish paths (context cancellation + ClientConn.Close)
	t.Run("stream_race_concurrent_multi_finish", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_CONCURRENT_MULTI_FINISH")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 10, "exactly 10 stream spans should be emitted (single-winner per stream)")
			for _, s := range streamSpans {
				assert.Equal(c, "/TestService/Stream", s.Path)
				assert.NotZero(c, s.Status)
			}
		}, 15*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 8. Stream interceptor exercises unrelated existing stream before streamer()
	t.Run("stream_interceptor_unrelated_withretry_before_streamer", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_INTERCEPTOR_BEFORE")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamASpans, streamBSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamASpans = append(streamASpans, s)
				} else if s.Path == "/TestService/StreamB" {
					streamBSpans = append(streamBSpans, s)
				}
			}
			assert.Len(c, streamASpans, 1, "exactly one span for stream A")
			assert.Len(c, streamBSpans, 1, "exactly one span for stream B")
			if len(streamASpans) == 1 && len(streamBSpans) == 1 {
				assert.NotEqual(c, streamASpans[0].SpanID, streamBSpans[0].SpanID, "distinct SpanIDs for streams A and B")
				assert.NotZero(c, streamASpans[0].TraceID)
				assert.NotZero(c, streamBSpans[0].TraceID)
				assert.Equal(c, "/TestService/Stream", streamASpans[0].Path)
				assert.Equal(c, "/TestService/StreamB", streamBSpans[0].Path)
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 9. Stream interceptor exercises unrelated existing stream after streamer()
	t.Run("stream_interceptor_unrelated_withretry_after_streamer", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_INTERCEPTOR_AFTER")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamASpans, streamBSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamASpans = append(streamASpans, s)
				} else if s.Path == "/TestService/StreamB" {
					streamBSpans = append(streamBSpans, s)
				}
			}
			assert.Len(c, streamASpans, 1, "exactly one span for stream A")
			assert.Len(c, streamBSpans, 1, "exactly one span for stream B")
			if len(streamASpans) == 1 && len(streamBSpans) == 1 {
				assert.NotEqual(c, streamASpans[0].SpanID, streamBSpans[0].SpanID, "distinct SpanIDs for streams A and B")
				assert.NotZero(c, streamASpans[0].TraceID)
				assert.NotZero(c, streamBSpans[0].TraceID)
				assert.Equal(c, "/TestService/Stream", streamASpans[0].Path)
				assert.Equal(c, "/TestService/StreamB", streamBSpans[0].Path)
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})
}

func TestGRPCClientStreamStrippedLifecycle(t *testing.T) {
	bin := buildGRPCNestedClientTargetStripped(t)
	send, collector, tracer := startGRPCNestedClientTarget(t, bin)

	// 1. Normal streaming RPC (finishes with io.EOF): must produce status == 0
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
			assert.Len(c, streamSpans, 1, "exactly one stream span should be emitted upon finish")
			if len(streamSpans) == 1 {
				assert.Equal(c, "/TestService/Stream", streamSpans[0].Path)
				assert.Equal(c, 0, streamSpans[0].Status, "normal stream finish with io.EOF must have status 0")
				assert.True(c, streamSpans[0].TraceID.IsValid())
				assert.True(c, streamSpans[0].SpanID.IsValid())
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})

	// 2. errors.New("EOF"): must remain non-zero error status
	t.Run("stream_err_new_eof", func(t *testing.T) {
		collector.clear()
		res := send("STREAM_ERR_NEW_EOF")
		require.Contains(t, res, "STATUS=OK")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			grpcSpans := collector.getGRPCClientSpans()
			var streamSpans []request.Span
			for _, s := range grpcSpans {
				if s.Path == "/TestService/Stream" {
					streamSpans = append(streamSpans, s)
				}
			}
			assert.Len(c, streamSpans, 1, "exactly one stream span should be emitted upon finish")
			if len(streamSpans) == 1 {
				assert.Equal(c, "/TestService/Stream", streamSpans[0].Path)
				assert.NotEqual(c, 0, streamSpans[0].Status, "errors.New(\"EOF\") must produce error status != 0")
				assert.True(c, streamSpans[0].TraceID.IsValid())
				assert.True(c, streamSpans[0].SpanID.IsValid())
			}
		}, 10*time.Second, 100*time.Millisecond)

		assertNoStaleStreams(t, tracer)
	})
}
