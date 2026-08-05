// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpuevent

import (
	"bytes"
	"log/slog"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func rawGPUEvent[T any](event *T) []byte {
	raw := unsafe.Slice((*byte)(unsafe.Pointer(event)), int(unsafe.Sizeof(*event)))
	return bytes.Clone(raw)
}

func assertGPUTraceContext(t *testing.T, span request.Span) {
	t.Helper()

	assert.Equal(t, trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, span.TraceID)
	assert.Equal(t, trace.SpanID{17, 18, 19, 20, 21, 22, 23, 24}, span.SpanID)
	assert.Equal(t, trace.SpanID{25, 26, 27, 28, 29, 30, 31, 32}, span.ParentSpanID)
	assert.Equal(t, uint8(ebpfcommon.TPFlagRandom), span.TraceFlags)
	assert.True(t, span.ParentRemote)
	assert.True(t, span.BPFDecision)
}

func TestProcessCudaEventPropagatesTraceContext(t *testing.T) {
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{17, 18, 19, 20, 21, 22, 23, 24}
	parentSpanID := trace.SpanID{25, 26, 27, 28, 29, 30, 31, 32}

	kernelLaunch := GPUCudaKernelLaunchInfo{Flags: EventTypeKernelLaunch}
	copy(kernelLaunch.Tp.TraceId[:], traceID[:])
	copy(kernelLaunch.Tp.SpanId[:], spanID[:])
	copy(kernelLaunch.Tp.ParentId[:], parentSpanID[:])
	kernelLaunch.Tp.Flags = ebpfcommon.TPFlagRandom
	kernelLaunch.Tp.ParentRemote = 1
	kernelLaunch.Tp.SamplingDecision = 1

	malloc := GPUCudaMallocInfo{Flags: EventTypeMalloc}
	copy(malloc.Tp.TraceId[:], traceID[:])
	copy(malloc.Tp.SpanId[:], spanID[:])
	copy(malloc.Tp.ParentId[:], parentSpanID[:])
	malloc.Tp.Flags = ebpfcommon.TPFlagRandom
	malloc.Tp.ParentRemote = 1
	malloc.Tp.SamplingDecision = 1

	memcpy := GPUCudaMemcpyInfo{Flags: EventTypeMemcpy}
	copy(memcpy.Tp.TraceId[:], traceID[:])
	copy(memcpy.Tp.SpanId[:], spanID[:])
	copy(memcpy.Tp.ParentId[:], parentSpanID[:])
	memcpy.Tp.Flags = ebpfcommon.TPFlagRandom
	memcpy.Tp.ParentRemote = 1
	memcpy.Tp.SamplingDecision = 1

	graphLaunch := GPUCudaGraphLaunchInfo{Flags: EventTypeGraphLaunch}
	copy(graphLaunch.Tp.TraceId[:], traceID[:])
	copy(graphLaunch.Tp.SpanId[:], spanID[:])
	copy(graphLaunch.Tp.ParentId[:], parentSpanID[:])
	graphLaunch.Tp.Flags = ebpfcommon.TPFlagRandom
	graphLaunch.Tp.ParentRemote = 1
	graphLaunch.Tp.SamplingDecision = 1

	tests := []struct {
		name      string
		rawSample []byte
		eventType request.EventType
	}{
		{
			name:      "kernel launch",
			rawSample: rawGPUEvent(&kernelLaunch),
			eventType: request.EventTypeGPUCudaKernelLaunch,
		},
		{
			name:      "malloc",
			rawSample: rawGPUEvent(&malloc),
			eventType: request.EventTypeGPUCudaMalloc,
		},
		{
			name:      "memcpy",
			rawSample: rawGPUEvent(&memcpy),
			eventType: request.EventTypeGPUCudaMemcpy,
		},
		{
			name:      "graph launch",
			rawSample: rawGPUEvent(&graphLaunch),
			eventType: request.EventTypeGPUCudaGraphLaunch,
		},
	}

	tracer := &Tracer{log: slog.Default()}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span, ignore, err := tracer.processCudaEvent(&ringbuf.Record{RawSample: tt.rawSample})

			require.NoError(t, err)
			assert.False(t, ignore)
			assert.Equal(t, tt.eventType, span.Type)
			assertGPUTraceContext(t, span)
		})
	}
}
