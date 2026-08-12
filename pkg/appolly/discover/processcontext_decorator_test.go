// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package discover

import (
	"log/slog"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	processcontextpb "go.opentelemetry.io/proto/otlp/processcontext/v1development"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const (
	otelCtxSignature  = "OTEL_CTX"
	otelCtxVersion    = uint32(2)
	otelCtxHeaderSize = 32
)

// writeOTELCTXHeader writes a 32-byte OTEL_CTX header into buf:
//
//	[0:8]   signature "OTEL_CTX"
//	[8:12]  version (uint32 LE)
//	[12:16] payload size (uint32 LE)
//	[16:24] monotonic published-at timestamp (uint64 LE)
//	[24:32] payload pointer (uint64 LE)
func writeOTELCTXHeader(buf []byte, payloadSize uint32, payloadPtr uint64, publishedAt uint64) {
	copy(buf[0:8], otelCtxSignature)
	*(*uint32)(unsafe.Pointer(&buf[8])) = otelCtxVersion
	*(*uint32)(unsafe.Pointer(&buf[12])) = payloadSize
	*(*uint64)(unsafe.Pointer(&buf[16])) = publishedAt
	*(*uint64)(unsafe.Pointer(&buf[24])) = payloadPtr
}

// setupOTELCTXMapping creates a memfd named "OTEL_CTX", writes a valid header
// pointing at payload, and maps it into the current process.  The caller must
// call the returned cleanup function when done.
func setupOTELCTXMapping(t *testing.T, ctx *processcontextpb.ProcessContext) (cleanup func()) {
	t.Helper()

	payload, err := proto.Marshal(ctx)
	require.NoError(t, err)

	// Keep the payload alive for the duration of the mapping.
	payloadPtr := uint64(uintptr(unsafe.Pointer(&payload[0])))

	fd, err := unix.MemfdCreate(otelCtxSignature, 0)
	require.NoError(t, err)

	require.NoError(t, unix.Ftruncate(fd, otelCtxHeaderSize))

	mem, err := unix.Mmap(fd, 0, otelCtxHeaderSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	require.NoError(t, err)

	unix.Close(fd)

	writeOTELCTXHeader(mem, uint32(len(payload)), payloadPtr, 1)

	return func() {
		_ = unix.Munmap(mem)
		// Keep payload alive until cleanup.
		_ = payload
	}
}

func newTestPCD() *processContextDecorator {
	return &processContextDecorator{
		log:          slog.Default(),
		pollInterval: time.Second,
		tracked:      make(map[app.PID]*processEntry),
	}
}

func newTestEvent(pid app.PID) Event[ebpf.Instrumentable] {
	fi := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{},
		CmdExePath: "/bin/test",
		Pid:        pid,
	})
	return Event[ebpf.Instrumentable]{
		Type: EventCreated,
		Obj:  ebpf.Instrumentable{FileInfo: fi},
	}
}

func TestProcessContextDecorator_HandleCreated_NoMapping(t *testing.T) {
	pcd := newTestPCD()
	ev := newTestEvent(app.PID(os.Getpid()))

	// Without setting up a mapping the event should pass through unchanged.
	pcd.handleCreated(&ev)

	attrs := ev.Obj.FileInfo.ServiceAttrs()
	assert.Nil(t, attrs.Metadata)
}

func TestProcessContextDecorator_HandleCreated_ResourceAttributes(t *testing.T) {
	ctx := &processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{
			Attributes: []*commonpb.KeyValue{
				{
					Key: "service.name",
					Value: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "my-service"},
					},
				},
				{
					Key: "service.namespace",
					Value: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "my-ns"},
					},
				},
			},
		},
	}

	cleanup := setupOTELCTXMapping(t, ctx)
	defer cleanup()

	pcd := newTestPCD()
	ev := newTestEvent(app.PID(os.Getpid()))
	pcd.handleCreated(&ev)

	fi := ev.Obj.FileInfo
	attrs := fi.ServiceAttrs()

	require.NotNil(t, attrs.Metadata)
	assert.Equal(t, "my-service", attrs.Metadata[attr.ServiceName])
	assert.Equal(t, "my-ns", attrs.Metadata[attr.ServiceNamespace])

	// Service UID should be populated from the resource attributes.
	assert.Equal(t, "my-service", attrs.UID.Name)
	assert.Equal(t, "my-ns", attrs.UID.Namespace)
}

func TestProcessContextDecorator_HandleCreated_ExtraAttributes(t *testing.T) {
	ctx := &processcontextpb.ProcessContext{
		ExtraAttributes: []*commonpb.KeyValue{
			{
				Key: "custom.key",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{StringValue: "custom-value"},
				},
			},
		},
	}

	cleanup := setupOTELCTXMapping(t, ctx)
	defer cleanup()

	pcd := newTestPCD()
	ev := newTestEvent(app.PID(os.Getpid()))
	pcd.handleCreated(&ev)

	attrs := ev.Obj.FileInfo.ServiceAttrs()
	require.NotNil(t, attrs.Metadata)
	assert.Equal(t, "custom-value", attrs.Metadata[attr.Name("custom.key")])
}

func TestProcessContextDecorator_HandleCreated_NonStringAttributesSkipped(t *testing.T) {
	ctx := &processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{
			Attributes: []*commonpb.KeyValue{
				{
					Key: "numeric.attr",
					Value: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_IntValue{IntValue: 42},
					},
				},
				{
					Key: "service.name",
					Value: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "svc"},
					},
				},
			},
		},
	}

	cleanup := setupOTELCTXMapping(t, ctx)
	defer cleanup()

	pcd := newTestPCD()
	ev := newTestEvent(app.PID(os.Getpid()))
	pcd.handleCreated(&ev)

	attrs := ev.Obj.FileInfo.ServiceAttrs()
	require.NotNil(t, attrs.Metadata)
	// The integer attribute should have been skipped.
	_, ok := attrs.Metadata[attr.Name("numeric.attr")]
	assert.False(t, ok)
	// The string attribute should be present.
	assert.Equal(t, "svc", attrs.Metadata[attr.ServiceName])
}

func TestProcessContextDecorator_Poll_PicksUpLateMapping(t *testing.T) {
	pcd := newTestPCD()
	ev := newTestEvent(app.PID(os.Getpid()))

	// Simulate process creation before the SDK has registered its mapping.
	pcd.handleCreated(&ev)
	assert.Nil(t, ev.Obj.FileInfo.ServiceAttrs().Metadata, "no attributes expected before mapping is set up")

	// Now the SDK publishes the mapping.
	ctx := &processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{
			Attributes: []*commonpb.KeyValue{
				{
					Key: "service.name",
					Value: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "late-service"},
					},
				},
			},
		},
	}
	cleanup := setupOTELCTXMapping(t, ctx)
	defer cleanup()

	// poll() should detect the new mapping and apply the attributes.
	pcd.poll()

	attrs := ev.Obj.FileInfo.ServiceAttrs()
	require.NotNil(t, attrs.Metadata)
	assert.Equal(t, "late-service", attrs.Metadata[attr.ServiceName])
}

func TestProcessContextDecorator_Poll_PicksUpUpdatedContext(t *testing.T) {
	// First mapping version.
	v1 := &processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{
			Attributes: []*commonpb.KeyValue{
				{
					Key: "service.name",
					Value: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "v1-service"},
					},
				},
			},
		},
	}

	payload1, err := proto.Marshal(v1)
	require.NoError(t, err)

	fd, err := unix.MemfdCreate(otelCtxSignature, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Ftruncate(fd, otelCtxHeaderSize))

	mem, err := unix.Mmap(fd, 0, otelCtxHeaderSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(mem) }()
	unix.Close(fd)

	writeOTELCTXHeader(mem, uint32(len(payload1)), uint64(uintptr(unsafe.Pointer(&payload1[0]))), 1)

	pcd := newTestPCD()
	ev := newTestEvent(app.PID(os.Getpid()))
	pcd.handleCreated(&ev)

	require.Equal(t, "v1-service", ev.Obj.FileInfo.ServiceAttrs().Metadata[attr.ServiceName])

	// SDK updates the context (new timestamp).
	v2 := &processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{
			Attributes: []*commonpb.KeyValue{
				{
					Key: "service.name",
					Value: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{StringValue: "v2-service"},
					},
				},
			},
		},
	}

	payload2, err := proto.Marshal(v2)
	require.NoError(t, err)

	writeOTELCTXHeader(mem, uint32(len(payload2)), uint64(uintptr(unsafe.Pointer(&payload2[0]))), 2)

	pcd.poll()

	assert.Equal(t, "v2-service", ev.Obj.FileInfo.ServiceAttrs().Metadata[attr.ServiceName])
	// Ensure the payload stays alive.
	_ = payload1
	_ = payload2
}

func TestProcessContextDecorator_AddAttribute_PreservesExplicitUID(t *testing.T) {
	pcd := newTestPCD()

	fi := execpkg.New(execpkg.Init{
		Service: svc.Attrs{
			UID: svc.UID{Name: "explicit-name", Namespace: "explicit-ns"},
		},
		CmdExePath: "/bin/test",
		Pid:        app.PID(os.Getpid()),
	})

	pcd.addAttribute(fi, attr.ServiceName, "from-context")
	pcd.addAttribute(fi, attr.ServiceNamespace, "from-context-ns")

	attrs := fi.ServiceAttrs()
	// Metadata gets the value from the context.
	assert.Equal(t, "from-context", attrs.Metadata[attr.ServiceName])
	// The pre-existing UID must not be overwritten.
	assert.Equal(t, "explicit-name", attrs.UID.Name)
	assert.Equal(t, "explicit-ns", attrs.UID.Namespace)
}
