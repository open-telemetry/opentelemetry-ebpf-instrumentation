// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/exceptions"
)

const testExceptionRuntime = BpfExceptionRuntimeK_exceptionRuntimeJava

func registerTestExceptionDecoder(t *testing.T) {
	t.Helper()
	previous, registered := exceptionPayloadDecoders[testExceptionRuntime]
	exceptionPayloadDecoders[testExceptionRuntime] = func(_ *BpfExceptionEventHeaderT, payload []byte, event *exceptions.Event) error {
		event.Type = string(payload)
		return nil
	}
	t.Cleanup(func() {
		if registered {
			exceptionPayloadDecoders[testExceptionRuntime] = previous
			return
		}
		delete(exceptionPayloadDecoders, testExceptionRuntime)
	})
}

func exceptionRecord(t *testing.T, owner BpfExceptionOwner, payload string) *ringbuf.Record {
	t.Helper()
	hdr := BpfExceptionEventHeaderT{
		CaptureNs:  1000,
		PayloadLen: uint32(len(payload)),
		Runtime:    uint8(testExceptionRuntime),
		Owner:      uint8(owner),
	}
	hdr.Pid.HostPid = 1
	hdr.Pid.UserPid = 1
	hdr.Tp.TraceId = [16]uint8{1}
	hdr.Tp.SpanId = [8]uint8{2}
	hdr.Tp.Flags = 1

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &hdr))
	buf.WriteString(payload)
	return &ringbuf.Record{RawSample: buf.Bytes()}
}

func exceptionFilter(enabled bool) ServiceFilter {
	filter := &TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	filter.AllowPID(1, 1, exec.New(exec.Init{Service: svc.Attrs{
		UID:        svc.UID{Name: "svc"},
		Exceptions: services.ExceptionsConfig{Enabled: enabled},
	}}), PIDTypeKProbes)
	return filter
}

func TestReadExceptionRecord(t *testing.T) {
	registerTestExceptionDecoder(t)

	event, ignore, err := ReadExceptionRecord(
		exceptionRecord(t, BpfExceptionOwnerK_exceptionOwnerOngoing, "java.lang.IllegalStateException"),
		exceptionFilter(true),
	)

	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "svc", event.Service.UID.Name)
	assert.Equal(t, "java.lang.IllegalStateException", event.Type)
	assert.Equal(t, trace.TraceID{1}, event.TraceID)
	assert.Equal(t, trace.SpanID{2}, event.SpanID)
	assert.Equal(t, trace.TraceFlags(1), event.TraceFlags)
	assert.False(t, event.Timestamp.IsZero())
}

func TestReadExceptionRecordWithoutOwner(t *testing.T) {
	registerTestExceptionDecoder(t)

	for _, owner := range []BpfExceptionOwner{
		BpfExceptionOwnerK_exceptionOwnerNone,
		BpfExceptionOwnerK_exceptionOwnerAmbiguous,
	} {
		event, ignore, err := ReadExceptionRecord(exceptionRecord(t, owner, "E"), exceptionFilter(true))

		require.NoError(t, err)
		require.False(t, ignore)
		assert.False(t, event.TraceID.IsValid())
		assert.False(t, event.SpanID.IsValid())
	}
}

func TestReadExceptionRecordIgnoresDisabledService(t *testing.T) {
	registerTestExceptionDecoder(t)

	_, ignore, err := ReadExceptionRecord(
		exceptionRecord(t, BpfExceptionOwnerK_exceptionOwnerOngoing, "E"),
		exceptionFilter(false),
	)

	require.NoError(t, err)
	assert.True(t, ignore)
}

func TestReadExceptionRecordRejectsMalformedRecords(t *testing.T) {
	registerTestExceptionDecoder(t)

	record := exceptionRecord(t, BpfExceptionOwnerK_exceptionOwnerOngoing, "payload")
	record.RawSample = record.RawSample[:len(record.RawSample)-1]
	_, ignore, err := ReadExceptionRecord(record, exceptionFilter(true))
	require.ErrorIs(t, err, errTruncatedExceptionRecord)
	assert.True(t, ignore)

	unknown := exceptionRecord(t, BpfExceptionOwnerK_exceptionOwnerOngoing, "E")
	unknown.RawSample[unsafe.Offsetof(BpfExceptionEventHeaderT{}.Runtime)] = 0
	_, ignore, err = ReadExceptionRecord(unknown, exceptionFilter(true))
	require.Error(t, err)
	assert.True(t, ignore)
}
