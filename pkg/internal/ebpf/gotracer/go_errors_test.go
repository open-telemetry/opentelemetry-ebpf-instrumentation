// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
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
	payload := &BpfGoExceptionPayloadT{Kind: kind, ValueType: 1, ValueRead: goValueStringType, Frames: uint16(len(pcs))}
	copy(payload.Message[:len(payload.Message)-1], message)
	copy(payload.Pcs[:], pcs)
	return payload
}

func mockGoExceptionFrames(t *testing.T, pcs []uint64, frames []goexec.GoFrame) {
	t.Helper()
	previous := goExceptionFrames
	goExceptionFrames = func(pid app.PID, got []uint64) ([]goexec.GoFrame, error) {
		assert.Equal(t, app.PID(1), pid)
		assert.Equal(t, pcs, got)
		return frames, nil
	}
	t.Cleanup(func() { goExceptionFrames = previous })
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
	mockGoExceptionFrames(t, []uint64{11, 21, 31, 41}, []goexec.GoFrame{
		{Function: "main.handler", File: "main.go", Line: 12},
		{Function: "net/http.HandlerFunc.ServeHTTP", File: "net/http/server.go", Line: 2322},
		{Function: "runtime.goexit", File: "runtime/asm_amd64.s", Line: 1700},
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
	mockGoExceptionFrames(t, []uint64{11, 21}, []goexec.GoFrame{
		{Function: "runtime.panicmem", File: "runtime/panic.go", Line: 262},
		{Function: "main.worker", File: "main.go", Line: 30},
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

type mapSymbolResolver map[uint64]goexec.GoFrame

func (r mapSymbolResolver) PCToFrame(pc uint64) (goexec.GoFrame, bool) {
	frame, ok := r[pc]
	return frame, ok
}

func (mapSymbolResolver) ValueType(addr uint64) (goexec.GoValueType, bool) {
	if addr == 1 {
		return goexec.GoValueType{Kind: uint8(reflect.String)}, true
	}
	return goexec.GoValueType{}, false
}

func (mapSymbolResolver) ReadOnlyData(uint64, uint64) ([]byte, bool) {
	return nil, false
}

func (mapSymbolResolver) SetDontNeed() {}
func (mapSymbolResolver) Close() error { return nil }

func registerGoExceptionSymbols(t *testing.T, resolver ebpfcommon.GoSymbolResolver) {
	t.Helper()
	previousType, previousData := goExceptionValueType, goExceptionReadOnlyData
	goExceptionValueType = func(_ app.PID, addr uint64) (goexec.GoValueType, bool) {
		return resolver.ValueType(addr)
	}
	goExceptionReadOnlyData = func(_ app.PID, addr, size uint64) ([]byte, bool) {
		return resolver.ReadOnlyData(addr, size)
	}
	t.Cleanup(func() {
		goExceptionValueType, goExceptionReadOnlyData = previousType, previousData
	})
}

func TestReadGoExceptionRecordPanicAfterPIDRemoval(t *testing.T) {
	goSymbols.BindPID(1, 7, 11, 0)
	goSymbols.RemovePID(1)
	for _, confirmedString := range []bool{false, true} {
		t.Run(fmt.Sprintf("confirmed string %t", confirmedString), func(t *testing.T) {
			payload := goExceptionPayload(goExceptionKindPanic, "boom")
			payload.ValueRead = 0
			if confirmedString {
				payload.ValueRead = goValueStringType
			}
			event, ignore, err := ebpfcommon.ReadExceptionRecord(
				goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
			)
			require.NoError(t, err)
			require.False(t, ignore)
			if confirmedString {
				require.Equal(t, "boom", event.Message)
				require.Equal(t, "panic: boom", event.Stacktrace)
			} else {
				require.Empty(t, event.Message)
				require.Equal(t, "panic:", event.Stacktrace)
			}
		})
	}
}

type runtimeErrorResolver struct {
	mapSymbolResolver
	message string
	reads   int
	typ     goexec.GoValueType
}

func (r *runtimeErrorResolver) ValueType(addr uint64) (goexec.GoValueType, bool) {
	if r.typ.Kind != 0 {
		return r.typ, addr == 2
	}
	return goexec.GoValueType{Kind: uint8(reflect.String), Methods: true, ErrorFunc: "runtime.errorString.Error"}, addr == 2
}

func (r *runtimeErrorResolver) ReadOnlyData(addr, size uint64) ([]byte, bool) {
	r.reads++
	if addr != 3 || size > uint64(len(r.message)) {
		return nil, false
	}
	return []byte(r.message[:size]), true
}

func TestReadGoExceptionRecordNilPointerMessage(t *testing.T) {
	const message = "invalid memory address or nil pointer dereference"
	for _, fromFile := range []bool{false, true} {
		name := "BPF bytes"
		if fromFile {
			name = "file fallback"
		}
		t.Run(name, func(t *testing.T) {
			resolver := &runtimeErrorResolver{message: message}
			registerGoExceptionSymbols(t, resolver)
			payload := goExceptionPayload(goExceptionKindPanic, message)
			payload.ValueType = 2
			payload.Value = [3]uint64{3, uint64(len(message))}
			payload.ValueRead = 1
			if fromFile {
				clear(payload.Message[:])
			}
			event, ignore, err := ebpfcommon.ReadExceptionRecord(
				goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
			)
			require.NoError(t, err)
			require.False(t, ignore)
			require.Equal(t, "runtime error: "+message, event.Message)
			require.Equal(t, "panic: runtime error: "+message, event.Stacktrace)
			if fromFile {
				require.Equal(t, 1, resolver.reads)
			} else {
				require.Zero(t, resolver.reads)
			}
		})
	}
}

type plainErrorResolver struct{ runtimeErrorResolver }

func (*plainErrorResolver) ValueType(addr uint64) (goexec.GoValueType, bool) {
	return goexec.GoValueType{Kind: uint8(reflect.String), Methods: true, ErrorFunc: "runtime.plainError.Error"}, addr == 2
}

func TestReadGoExceptionRecordFallbackStringFormat(t *testing.T) {
	for _, tc := range []struct {
		name, message, want string
	}{
		{"complete", "complete", "complete"},
		{"embedded NUL", "failed\x00details", "failed"},
		{"truncated", strings.Repeat("x", 140), strings.Repeat("x", 127)},
		{"partial UTF-8", strings.Repeat("x", 126) + "é", strings.Repeat("x", 126)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &plainErrorResolver{runtimeErrorResolver{message: tc.message}}
			registerGoExceptionSymbols(t, resolver)
			payload := goExceptionPayload(goExceptionKindPanic, "")
			payload.ValueType = 2
			payload.ValueRead = goValueHeaderRead
			payload.Value = [3]uint64{3, uint64(len(tc.message))}
			event, ignore, err := ebpfcommon.ReadExceptionRecord(
				goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
			)
			require.NoError(t, err)
			require.False(t, ignore)
			require.Equal(t, tc.want, event.Message)
			require.Equal(t, 1, resolver.reads)
		})
	}
}

func TestReadGoExceptionRecordNilChannelFallback(t *testing.T) {
	const message = "close of nil channel"
	resolver := &plainErrorResolver{runtimeErrorResolver{message: message}}
	registerGoExceptionSymbols(t, resolver)
	payload := goExceptionPayload(goExceptionKindPanic, "")
	payload.ValueType = 2
	payload.Value = [3]uint64{3, uint64(len(message))}
	payload.ValueRead = 1

	event, ignore, err := ebpfcommon.ReadExceptionRecord(
		goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
	)
	require.NoError(t, err)
	require.False(t, ignore)
	require.Equal(t, message, event.Message)
	require.Equal(t, "panic: "+message, event.Stacktrace)
	require.Equal(t, 1, resolver.reads)
}

func TestReadGoExceptionRecordMappedFileFallback(t *testing.T) {
	const message = "invalid memory address or nil pointer dereference"
	resolver := &runtimeErrorResolver{
		message: message,
		typ: goexec.GoValueType{
			Kind: uint8(reflect.Struct), Methods: true,
			ErrorFunc: "runtime.errorAddressString.Error",
		},
	}
	registerGoExceptionSymbols(t, resolver)
	payload := goExceptionPayload(goExceptionKindPanic, "")
	payload.ValueType = 2
	payload.Value = [3]uint64{3, uint64(len(message))}
	payload.ValueRead = 1

	event, ignore, err := ebpfcommon.ReadExceptionRecord(
		goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
	)
	require.NoError(t, err)
	require.False(t, ignore)
	require.Equal(t, "runtime error: "+message, event.Message)
	require.Equal(t, "panic: runtime error: "+message, event.Stacktrace)
	require.Equal(t, 1, resolver.reads)
}

func TestReadGoExceptionRecordScalarMessage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  reflect.Kind
		value uint64
		want  string
	}{
		{"int", reflect.Int, 5, "5"},
		{"negative int", reflect.Int, ^uint64(4), "-5"},
		{"int8", reflect.Int8, 128, "-128"},
		{"int16", reflect.Int16, 32768, "-32768"},
		{"int32", reflect.Int32, 1 << 31, "-2147483648"},
		{"int64", reflect.Int64, 1 << 63, "-9223372036854775808"},
		{"uint", reflect.Uint, ^uint64(0), "18446744073709551615"},
		{"uint8", reflect.Uint8, 255, "255"},
		{"uint16", reflect.Uint16, 65535, "65535"},
		{"uint32", reflect.Uint32, 1<<32 - 1, "4294967295"},
		{"uint64", reflect.Uint64, ^uint64(0), "18446744073709551615"},
		{"uintptr", reflect.Uintptr, 5, "5"},
		{"true", reflect.Bool, 1, "true"},
		{"false", reflect.Bool, 0, "false"},
		{"invalid bool", reflect.Bool, 2, ""},
		{"float", reflect.Float64, 5, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"read", "unreadable", "named", "methods"} {
				t.Run(mode, func(t *testing.T) {
					resolver := &runtimeErrorResolver{typ: goexec.GoValueType{
						Kind: uint8(tc.kind), Predeclared: mode != "named", Methods: mode == "methods",
					}}
					registerGoExceptionSymbols(t, resolver)
					payload := goExceptionPayload(goExceptionKindPanic, "")
					payload.ValueType = 2
					payload.Value[0] = tc.value
					if mode != "unreadable" {
						payload.ValueRead = goValueScalarRead
					}
					event, ignore, err := ebpfcommon.ReadExceptionRecord(
						goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
					)
					require.NoError(t, err)
					require.False(t, ignore)
					want := ""
					if mode == "read" {
						want = tc.want
					}
					require.Equal(t, want, event.Message)
				})
			}
		})
	}
}

func TestReadGoExceptionRecordStandardErrorMessage(t *testing.T) {
	for _, method := range []string{"errors.(*errorString).Error", "fmt.(*wrapError).Error", "fmt.(*wrapErrors).Error", "main.(*customError).Error"} {
		for _, fromFile := range []bool{false, true} {
			name := method + "/BPF bytes"
			if fromFile {
				name = method + "/file fallback"
			}
			t.Run(name, func(t *testing.T) {
				resolver := &runtimeErrorResolver{
					message: "boom",
					typ: goexec.GoValueType{
						Kind: uint8(reflect.Pointer), Methods: true,
						ErrorFunc: method,
					},
				}
				registerGoExceptionSymbols(t, resolver)
				payload := goExceptionPayload(goExceptionKindPanic, "boom")
				payload.ValueType = 2
				payload.Value = [3]uint64{3, 4}
				payload.ValueRead = goValueHeaderRead
				if fromFile {
					clear(payload.Message[:])
				}
				event, ignore, err := ebpfcommon.ReadExceptionRecord(
					goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
				)
				require.NoError(t, err)
				require.False(t, ignore)
				if method != "main.(*customError).Error" {
					require.Equal(t, "boom", event.Message)
					if fromFile {
						require.Equal(t, 1, resolver.reads)
					} else {
						require.Zero(t, resolver.reads)
					}
				} else {
					require.Empty(t, event.Message)
					require.Zero(t, resolver.reads)
				}
			})
		}
	}
}

func TestReadGoExceptionRecordUnknownStructMessage(t *testing.T) {
	for _, message := range []string{"internal value", ""} {
		t.Run("captured="+message, func(t *testing.T) {
			resolver := &runtimeErrorResolver{
				message: "internal value",
				typ: goexec.GoValueType{
					Kind: uint8(reflect.Struct), Methods: true,
					ErrorFunc: "main.customError.Error",
				},
			}
			registerGoExceptionSymbols(t, resolver)
			payload := goExceptionPayload(goExceptionKindPanic, message)
			payload.ValueType = 2
			payload.Value = [3]uint64{3, uint64(len(resolver.message))}
			payload.ValueRead = 1
			event, ignore, err := ebpfcommon.ReadExceptionRecord(
				goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
			)
			require.NoError(t, err)
			require.False(t, ignore)
			require.Empty(t, event.Message)
			require.Equal(t, "panic:", event.Stacktrace)
			require.Zero(t, resolver.reads)
		})
	}
}

func TestReadGoExceptionRecordNilPointerUnreadableMessage(t *testing.T) {
	resolver := &runtimeErrorResolver{}
	registerGoExceptionSymbols(t, resolver)
	payload := goExceptionPayload(goExceptionKindPanic, "")
	payload.ValueType = 2
	payload.Value = [3]uint64{99, 48}
	payload.ValueRead = 1

	event, ignore, err := ebpfcommon.ReadExceptionRecord(
		goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
	)
	require.NoError(t, err)
	require.False(t, ignore)
	require.Equal(t, "go.panic", event.Type)
	require.Empty(t, event.Message)
	require.Equal(t, "panic:", event.Stacktrace)
	require.Equal(t, 1, resolver.reads)
}

func TestReadGoExceptionRecordBoundsMessage(t *testing.T) {
	for _, flags := range []uint8{0, goValueHeaderRead, goValueTailRead, goValueHeaderRead | goValueTailRead} {
		t.Run(fmt.Sprintf("read flags %d", flags), func(t *testing.T) {
			resolver := &runtimeErrorResolver{
				typ: goexec.GoValueType{
					Kind: uint8(reflect.Struct), Methods: true,
					ErrorFunc: "runtime.boundsError.Error",
				},
			}
			registerGoExceptionSymbols(t, resolver)
			payload := goExceptionPayload(goExceptionKindPanic, "")
			payload.ValueType = 2
			payload.ValueRead = flags
			payload.Value = [3]uint64{5, 3, 1}
			event, ignore, err := ebpfcommon.ReadExceptionRecord(
				goExceptionRecord(t, ebpfcommon.BpfExceptionOwnerK_exceptionOwnerNone, payload), &goExceptionServiceFilter{},
			)
			require.NoError(t, err)
			require.False(t, ignore)
			require.Equal(t, "go.panic", event.Type)
			if flags == goValueHeaderRead|goValueTailRead {
				require.Equal(t, "runtime error: index out of range [5] with length 3", event.Message)
			} else {
				require.Empty(t, event.Message)
			}
			require.Zero(t, resolver.reads)
		})
	}
}
