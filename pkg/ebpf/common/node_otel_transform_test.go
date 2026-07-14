// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func nodeSpanRecordBytes(t *testing.T, ev *NodeSpanEvent, payload string) *ringbuf.Record {
	t.Helper()

	require.LessOrEqual(t, len(payload), len(ev.Payload))
	copy(ev.Payload[:], payload)
	ev.PayloadLen = uint32(len(payload))
	ev.Type = EventNodeSpan

	raw := unsafe.Slice((*byte)(unsafe.Pointer(ev)), unsafe.Sizeof(*ev))

	return &ringbuf.Record{RawSample: raw}
}

func TestReadNodeSpanEventIntoSpan(t *testing.T) {
	ev := NodeSpanEvent{
		HasParentCtx: 1,
		EndKtime:     1_000_000_000,
	}
	for i := range ev.ParentTraceId {
		ev.ParentTraceId[i] = uint8(i + 1)
	}
	for i := range ev.ParentSpanId {
		ev.ParentSpanId[i] = uint8(i + 0xa0)
	}

	payload := `{"v":1,"name":"charge-card","tid":"5b8efff798038103d269b633813fc60c",` +
		`"sid":"eee19b7ec3c1b174","psid":"b7ad6b7169203331","kind":0,` +
		`"startNs":"1700000000000000000","durNs":"250000000","status":2,"statusMsg":"boom",` +
		`"attrs":{"payment.provider":"stripe","amount":42,"ratio":0.5,"sampled":true},` +
		`"scope":"checkout"}`

	span, ignore, err := ReadNodeSpanEventIntoSpan(nodeSpanRecordBytes(t, &ev, payload))
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeManualSpan, span.Type)
	assert.Equal(t, "charge-card", span.Method)
	assert.Equal(t, "boom", span.Path)
	// Payload status 2 is OTel JS ERROR; it must map to Go codes.Error, which
	// the traces pipeline renders as STATUS_CODE_ERROR (the JS and Go enums
	// assign OK/ERROR opposite values).
	assert.Equal(t, int(codes.Error), span.Status)

	// timing: anchored on the BPF monotonic end timestamp
	assert.Equal(t, int64(1_000_000_000), span.End)
	assert.Equal(t, int64(750_000_000), span.Start)
	assert.Equal(t, span.Start, span.RequestStart)

	// trace context: re-anchored on the BPF-provided request context,
	// but the in-bridge parent span id wins over the server span id
	assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", span.TraceID.String())
	assert.Equal(t, "eee19b7ec3c1b174", span.SpanID.String())
	assert.Equal(t, "b7ad6b7169203331", span.ParentSpanID.String())

	// attributes: the Statement JSON must decode with the same struct shape
	// tracesgen.manualSpanAttributes uses
	var attrs []nodeSpanAttr
	require.NoError(t, json.Unmarshal([]byte(span.Statement), &attrs))
	require.Len(t, attrs, 4)

	byKey := map[string]nodeSpanAttr{}
	for _, a := range attrs {
		byKey[cstr(a.Key[:])] = a
	}

	require.Contains(t, byKey, "payment.provider")
	provider := byKey["payment.provider"]
	assert.Equal(t, uint8(attribute.STRING), provider.Vtype)
	assert.Equal(t, "stripe", cstr(provider.Value[:]))

	require.Contains(t, byKey, "amount")
	amount := byKey["amount"]
	assert.Equal(t, uint8(attribute.INT64), amount.Vtype)
	assert.Equal(t, uint64(42), binary.LittleEndian.Uint64(amount.Value[:8]))

	require.Contains(t, byKey, "ratio")
	ratio := byKey["ratio"]
	assert.Equal(t, uint8(attribute.FLOAT64), ratio.Vtype)
	assert.InDelta(t, 0.5, math.Float64frombits(binary.LittleEndian.Uint64(ratio.Value[:8])), 1e-9)

	require.Contains(t, byKey, "sampled")
	sampled := byKey["sampled"]
	assert.Equal(t, uint8(attribute.BOOL), sampled.Vtype)
	assert.Equal(t, uint8(1), sampled.Value[0])
}

func TestReadNodeSpanEventIntoSpan_NoParentContext(t *testing.T) {
	ev := NodeSpanEvent{EndKtime: 2_000_000_000}

	payload := `{"v":1,"name":"standalone","tid":"5b8efff798038103d269b633813fc60c",` +
		`"sid":"eee19b7ec3c1b174","durNs":"1000","status":0,"attrs":{}}`

	span, ignore, err := ReadNodeSpanEventIntoSpan(nodeSpanRecordBytes(t, &ev, payload))
	require.NoError(t, err)
	require.False(t, ignore)

	// keeps the bridge-generated trace id, no parent
	assert.Equal(t, "5b8efff798038103d269b633813fc60c", span.TraceID.String())
	assert.False(t, span.ParentSpanID.IsValid())
	assert.Empty(t, span.Statement)
}

func TestReadNodeSpanEventIntoSpan_RootUnderServerSpan(t *testing.T) {
	ev := NodeSpanEvent{HasParentCtx: 1, EndKtime: 3_000_000_000}
	for i := range ev.ParentSpanId {
		ev.ParentSpanId[i] = uint8(i + 0xa0)
	}
	for i := range ev.ParentTraceId {
		ev.ParentTraceId[i] = uint8(i + 1)
	}

	// no psid: the bridge-root span parents under OBI's automatic server span
	payload := `{"v":1,"name":"root","tid":"5b8efff798038103d269b633813fc60c",` +
		`"sid":"eee19b7ec3c1b174","durNs":"1000","status":0}`

	span, _, err := ReadNodeSpanEventIntoSpan(nodeSpanRecordBytes(t, &ev, payload))
	require.NoError(t, err)

	assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", span.TraceID.String())
	assert.Equal(t, "a0a1a2a3a4a5a6a7", span.ParentSpanID.String())
}

func TestReadNodeSpanEventIntoSpan_Invalid(t *testing.T) {
	// malformed JSON
	ev := NodeSpanEvent{EndKtime: 1}
	_, ignore, err := ReadNodeSpanEventIntoSpan(nodeSpanRecordBytes(t, &ev, `{"name":`))
	require.Error(t, err)
	assert.True(t, ignore)

	// empty payload
	ev2 := NodeSpanEvent{EndKtime: 1}
	rec := nodeSpanRecordBytes(t, &ev2, "")
	_, ignore, err = ReadNodeSpanEventIntoSpan(rec)
	require.Error(t, err)
	assert.True(t, ignore)

	// missing name
	ev3 := NodeSpanEvent{EndKtime: 1}
	_, ignore, err = ReadNodeSpanEventIntoSpan(nodeSpanRecordBytes(t, &ev3,
		`{"sid":"eee19b7ec3c1b174","durNs":"1"}`))
	require.Error(t, err)
	assert.True(t, ignore)
}
