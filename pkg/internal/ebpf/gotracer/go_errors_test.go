// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func goExceptionRecord(t *testing.T, owner ebpfcommon.BpfExceptionOwner, payload *BpfGoExceptionPayloadT) *ringbuf.Record {
	t.Helper()
	hdr := ebpfcommon.BpfExceptionEventHeaderT{
		CaptureNs:  1000,
		PayloadLen: uint32(unsafe.Sizeof(*payload)),
		Runtime:    uint8(ebpfcommon.BpfExceptionRuntimeK_exceptionRuntimeGo),
		Owner:      uint8(owner),
	}
	hdr.Pid.HostPid = 1
	hdr.Pid.UserPid = 1
	hdr.Tp.TraceId = [16]uint8{1}
	hdr.Tp.SpanId = [8]uint8{2}

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &hdr))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, payload))
	return &ringbuf.Record{RawSample: buf.Bytes()}
}

func goExceptionPayload(kind uint8, message string, pcs ...uint64) *BpfGoExceptionPayloadT {
	payload := &BpfGoExceptionPayloadT{Kind: kind, Frames: uint16(len(pcs))}
	copy(payload.Message[:len(payload.Message)-1], message)
	copy(payload.Pcs[:], pcs)
	return payload
}

type mapSymbolResolver map[uint64]goexec.GoFrame

func (r mapSymbolResolver) PCToFrame(pc uint64) (goexec.GoFrame, bool) {
	frame, ok := r[pc]
	return frame, ok
}
func (mapSymbolResolver) SetDontNeed() {}
func (mapSymbolResolver) Close() error { return nil }

func registerGoExceptionSymbols(t *testing.T, frames mapSymbolResolver) {
	t.Helper()
	require.NoError(t, goSymbols.AddExecutable(7, 11, func() (ebpfcommon.GoSymbolSource, error) {
		return ebpfcommon.GoSymbolSource{
			Open:  func() (ebpfcommon.GoSymbolResolver, error) { return frames, nil },
			Close: func() error { return nil },
		}, nil
	}))
	goSymbols.BindPID(1, 7, 11, 0)
	t.Cleanup(func() {
		goSymbols.RemovePID(1)
		goSymbols.RemoveExecutable(7, 11)
	})
}

type goExceptionServiceFilter struct {
	ebpfcommon.IdentityPidsFilter
}

func (*goExceptionServiceFilter) Filter(spans []request.Span) []request.Span {
	for i := range spans {
		spans[i].Service = svc.Attrs{
			UID:        svc.UID{Name: "svc"},
			Exceptions: services.ExceptionsConfig{Enabled: true},
		}
	}
	return spans
}

func TestReadGoExceptionRecord(t *testing.T) {
	registerGoExceptionSymbols(t, mapSymbolResolver{
		10: {Function: "fmt.Errorf", File: "fmt/errors.go", Line: 26},
		20: {Function: "main.handler", File: "main.go", Line: 12},
		30: {Function: "net/http.HandlerFunc.ServeHTTP", File: "net/http/server.go", Line: 2322},
		40: {Function: "runtime.goexit", File: "runtime/asm_amd64.s", Line: 1700},
	})

	event, ignore, err := ebpfcommon.ReadExceptionRecord(
		goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerOngoing, goExceptionPayload(0, "lookup failed: timeout", 11, 21, 31, 41)),
		&goExceptionServiceFilter{},
	)

	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "go.error", event.Type)
	assert.Equal(t, "lookup failed: timeout", event.Message)
	assert.Equal(t, "main.handler(...)\n\tmain.go:12\n"+
		"net/http.HandlerFunc.ServeHTTP(...)\n\tnet/http/server.go:2322", event.Stacktrace)
	assert.EqualValues(t, 17, event.SeverityNumber)
	assert.Equal(t, trace.TraceID{1}, event.TraceID)
	assert.Equal(t, trace.SpanID{2}, event.SpanID)
}

func TestReadGoExceptionRecordPanicWithoutOwner(t *testing.T) {
	registerGoExceptionSymbols(t, mapSymbolResolver{
		10: {Function: "runtime.panicmem", File: "runtime/panic.go", Line: 262},
		20: {Function: "main.worker", File: "main.go", Line: 30},
	})

	event, ignore, err := ebpfcommon.ReadExceptionRecord(
		goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, goExceptionPayload(goExceptionKindPanic, "boom", 11, 21)),
		&goExceptionServiceFilter{},
	)

	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "go.panic", event.Type)
	assert.Equal(t, "boom", event.Message)
	assert.Equal(t, "panic: boom\n\nmain.worker(...)\n\tmain.go:30", event.Stacktrace,
		"unexported runtime frames are hidden, as runtime.Stack does")
	assert.EqualValues(t, 17, event.SeverityNumber)
	assert.False(t, event.TraceID.IsValid())
	assert.False(t, event.SpanID.IsValid())
}

func TestReadGoExceptionRecordBounds(t *testing.T) {
	payload := goExceptionPayload(0, "invalid \xff utf8")
	payload.Frames = 1000

	event, ignore, err := ebpfcommon.ReadExceptionRecord(
		goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload),
		&goExceptionServiceFilter{},
	)

	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "invalid  utf8", event.Message)
	assert.Empty(t, event.Stacktrace, "unregistered processes have no symbols")
}

func TestReadGoExceptionRecordTruncated(t *testing.T) {
	record := goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, goExceptionPayload(0, "x"))
	hdr := (*ebpfcommon.BpfExceptionEventHeaderT)(unsafe.Pointer(&record.RawSample[0]))
	hdr.PayloadLen = 4

	_, ignore, err := ebpfcommon.ReadExceptionRecord(record, &goExceptionServiceFilter{})

	require.Error(t, err)
	assert.True(t, ignore)
}

func TestGoStacktraceFramesOmitted(t *testing.T) {
	frames := []goexec.GoFrame{{Function: "main.recurse", File: "main.go", Line: 5}}

	assert.Equal(t, "main.recurse(...)\n\tmain.go:5\n... frames omitted",
		goStacktrace(false, "", frames, true), "the capture limit was hit before runtime.goexit")
	assert.Equal(t, "main.recurse(...)\n\tmain.go:5",
		goStacktrace(false, "", frames, false))
	assert.Equal(t, "main.recurse(...)\n\tmain.go:5",
		goStacktrace(false, "", append(frames, goexec.GoFrame{Function: "runtime.goexit"}), true),
		"a stack that reaches runtime.goexit is complete")
}

func TestGoStacktracePanicHeader(t *testing.T) {
	frames := []goexec.GoFrame{{Function: "main.handler", File: "main.go", Line: 9}}

	assert.Equal(t, "panic: boom\n\nmain.handler(...)\n\tmain.go:9", goStacktrace(true, "boom", frames, false))
	assert.Equal(t, "panic:\n\nmain.handler(...)\n\tmain.go:9", goStacktrace(true, "", frames, false),
		"an omitted or unreadable message leaves only the header")
	assert.Equal(t, "panic: boom", goStacktrace(true, "boom", nil, false))
}

func TestGoShowFrame(t *testing.T) {
	assert.True(t, goShowFrame("main.main"))
	assert.True(t, goShowFrame("net/http.(*conn).serve"))
	assert.True(t, goShowFrame("runtime.Goexit"))
	assert.False(t, goShowFrame("runtime.goexit"))
	assert.False(t, goShowFrame("runtime.sigpanic"))
}

func TestReadGoExceptionRecordMessage(t *testing.T) {
	for _, tc := range []struct {
		name, message, want string
	}{
		{"empty", "", ""},
		{"complete", "complete", "complete"},
		{"embedded NUL", "failed\x00details", "failed"},
		{"full", strings.Repeat("x", 127), strings.Repeat("x", 127)},
		{"truncated", strings.Repeat("x", 140), strings.Repeat("x", 127)},
		{"partial UTF-8", strings.Repeat("x", 126) + "é", strings.Repeat("x", 126)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := goExceptionPayload(goExceptionKindPanic, tc.message)
			event, _, err := ebpfcommon.ReadExceptionRecord(
				goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload),
				&goExceptionServiceFilter{},
			)
			require.NoError(t, err)
			assert.Equal(t, tc.want, event.Message)
		})
	}
}
