// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestCustomSpanTransportLive(t *testing.T) {
	require.Zero(t, os.Geteuid(), "live custom-span transport test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	pid := app.PID(os.Getpid())
	fileInfo := customSpanTransportFileInfo(t, pid)
	cfg := obi.DefaultConfig
	filters := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	tracer := New(filters, &cfg, imetrics.NoopReporter{})
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = filters
	processTracer := ebpftracer.NewProcessTracer(ebpftracer.Generic, []ebpftracer.Tracer{tracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, processTracer.Init(eventContext, &cfg))
	processTracer.AllowPID(pid, fileInfo.Ns(), fileInfo)

	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(8))
	spans := queue.Subscribe(msg.SubscriberName("custom-span-transport-live"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		processTracer.Run(ctx, eventContext, queue)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("timed out stopping custom-span event reader")
		}
		queue.Close()
	})

	payload := []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"00000000000000000000000000000001","spanId":"0000000000000002","parentSpanId":"0000000000000003","name":"custom.transport","kind":1,"startTimeUnixNano":"946684800000000000","endTimeUnixNano":"946684801000000000","attributes":[{"key":"transport.source","value":{"stringValue":"ioctl"}}]}]}]}]}`)
	packet := make([]byte, 8+len(payload))
	packet[0] = 8 // OperationType.CUSTOM_SPAN
	binary.NativeEndian.PutUint32(packet[4:8], uint32(len(payload)))
	copy(packet[8:], payload)
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, 0, 0x0b10b1, uintptr(unsafe.Pointer(&packet[0])))
	runtime.KeepAlive(packet)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type != request.EventTypeManualSpan || span.Method != "custom.transport" {
					continue
				}
				require.Equal(t, trace.TraceID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, span.TraceID)
				require.Equal(t, trace.SpanID{0, 0, 0, 0, 0, 0, 0, 2}, span.SpanID)
				require.Equal(t, trace.SpanID{0, 0, 0, 0, 0, 0, 0, 3}, span.ParentSpanID)
				require.Greater(t, span.End, span.Start)
				require.Equal(t, app.PID(os.Getpid()), span.Pid.HostPID)
				require.NotEmpty(t, span.ManualOTelJSON)
				service := &svc.Attrs{
					UID:         svc.UID{Name: "custom-span-live"},
					SDKLanguage: svc.InstrumentableGolang,
				}
				cache := expirable2.NewLRU[svc.UID, []attribute.KeyValue](10, nil, 0)
				traces := tracesgen.GenerateTracesWithAttributes(
					cache,
					service,
					nil,
					&metadata.NodeMeta{},
					[]tracesgen.TraceSpanAndAttributes{{Span: &span}},
					"custom-span-transport-live",
				)
				require.Equal(t, 1, traces.ResourceSpans().Len())
				exported := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
				require.Equal(t, "custom.transport", exported.Name())
				require.Equal(t, trace.TraceID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, trace.TraceID(exported.TraceID()))
				require.Equal(t, trace.SpanID{0, 0, 0, 0, 0, 0, 0, 2}, trace.SpanID(exported.SpanID()))
				require.Equal(t, trace.SpanID{0, 0, 0, 0, 0, 0, 0, 3}, trace.SpanID(exported.ParentSpanID()))
				require.Equal(t, uint64(946684800000000000), uint64(exported.StartTimestamp()))
				require.Equal(t, uint64(946684801000000000), uint64(exported.EndTimestamp()))
				value, found := exported.Attributes().Get("transport.source")
				require.True(t, found)
				require.Equal(t, "ioctl", value.Str())
				return
			}
		case <-deadline:
			t.Fatal("custom span was not delivered through the eBPF span pipeline")
		}
	}
}

func customSpanTransportFileInfo(t *testing.T, pid app.PID) *discexec.FileInfo {
	t.Helper()
	procPath := filepath.Join("/proc", fmt.Sprint(pid), "exe")
	exePath, err := os.Readlink(procPath)
	require.NoError(t, err)
	info, err := os.Stat(procPath)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	ns, err := procs.FindNamespace(pid)
	require.NoError(t, err)
	return discexec.New(discexec.Init{
		Service:        svc.Attrs{UID: svc.UID{Name: "custom-span-live", Namespace: "integration-test"}},
		CmdExePath:     exePath,
		ProExeLinkPath: procPath,
		Pid:            pid,
		Dev:            uint64(stat.Dev),
		Ino:            stat.Ino,
		Ns:             ns,
	})
}
