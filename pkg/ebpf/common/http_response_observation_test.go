// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func clientRequestEvent() *BPFHTTPInfo {
	event := &BPFHTTPInfo{
		Type:            uint8(request.EventTypeHTTPClient),
		StartMonotimeNs: 1000,
		EndMonotimeNs:   2000,
		Len:             64,
	}
	event.Pid.HostPid = 4242
	copy(event.Buf[:], "GET /r HTTP/1.1\r\nHost: relay:9100\r\n\r\n")

	return event
}

// The span must survive. Dropping the record would reintroduce the silently-missing
// spans #767 fixed.
func TestHTTPInfoEventToSpan_UnparsedResponseIsStillReported(t *testing.T) {
	event := clientRequestEvent()
	event.ResponseObservation = bpfResponseReceived

	span, ignore, err := HTTPInfoEventToSpan(nil, event)
	require.NoError(t, err)
	require.False(t, ignore, "the span is emitted, not dropped")

	assert.NotEqual(t, request.ResponseParsed, span.ResponseObservation)
	assert.Equal(t, 0, span.Status, "no status is invented for a response nobody saw")
	assert.Equal(t, request.StatusCodeUnset, request.SpanStatusCode(&span))
	assert.Equal(t, "GET", span.Method)
	assert.Equal(t, "/r", span.Path)
}

// The recorded end time is when the socket went away, not when the request finished, so
// the duration overstates the request and stays out of every duration instrument. It
// still counts in the service graph, whose request counter stands on its own.
func TestHTTPInfoEventToSpan_UnknownOutcomeHasNoMeasuredDuration(t *testing.T) {
	event := clientRequestEvent()
	event.ResponseObservation = bpfResponseReceived

	span, _, err := HTTPInfoEventToSpan(nil, event)
	require.NoError(t, err)

	assert.True(t, request.IgnoreDurations(&span))
	assert.False(t, request.IgnoreMetrics(&span),
		"the span is withheld from durations, not from every metric")
	assert.False(t, request.IgnoreTraces(&span), "the trace still carries the call")
}

// Nothing came back, so the close is the end of the request and its duration is a
// measurement. The status stays Unset: a peer that reset the connection and a client
// that stopped waiting look alike here.
//
// Measured against a peer that resets mid-response, sk_err reached tcp_close set in 0 of
// 200 loopback failures and 0 of 9,936 containerized ones. sock_error() consumes it with
// an xchg on the application's read. A control that never reads before closing kept it
// in 200 of 200.
func TestHTTPInfoEventToSpan_AbsentResponseIsMeasuredButNotJudged(t *testing.T) {
	event := clientRequestEvent()
	event.ResponseObservation = bpfResponseSilent

	span, ignore, err := HTTPInfoEventToSpan(nil, event)
	require.NoError(t, err)
	require.False(t, ignore, "the span is emitted, not dropped")

	assert.NotEqual(t, request.ResponseParsed, span.ResponseObservation, "no response was read, so there is no status")
	assert.Equal(t, 0, span.Status)
	assert.Equal(t, request.StatusCodeUnset, request.SpanStatusCode(&span),
		"OBI cannot tell a reset from a client that gave up, so it asserts neither")
	assert.False(t, request.IgnoreDurations(&span),
		"the close is a real event at a real time, so the duration is a measurement")
	assert.False(t, request.IgnoreMetrics(&span))
}

// The response arrived and no probe could parse it. The end time came from those bytes,
// so the duration is a measurement even though the status is missing. This is the case a
// reused connection produces: the request is finished by its response, not by a close.
func TestHTTPInfoEventToSpan_UnreadResponseKeepsItsDuration(t *testing.T) {
	event := clientRequestEvent()
	event.ResponseObservation = bpfResponseUnread

	span, ignore, err := HTTPInfoEventToSpan(nil, event)
	require.NoError(t, err)
	require.False(t, ignore, "the span is emitted, not dropped")

	assert.Equal(t, request.ResponseUnread, span.ResponseObservation)
	assert.Equal(t, 0, span.Status, "no status is invented for a response nobody parsed")
	assert.Equal(t, request.StatusCodeUnset, request.SpanStatusCode(&span))
	assert.False(t, request.IgnoreDurations(&span),
		"the response's own bytes ended the request, so the duration is a measurement")
	assert.False(t, request.IgnoreMetrics(&span))
	assert.False(t, request.IgnoreTraces(&span))
}

// No span on this path names an error type.
func TestErrorType_NoUnobservedCaseNamesAFailure(t *testing.T) {
	for _, observation := range []uint8{bpfResponseReceived, bpfResponseSilent, bpfResponseUnread} {
		event := clientRequestEvent()
		event.ResponseObservation = observation

		span, _, err := HTTPInfoEventToSpan(nil, event)
		require.NoError(t, err)

		require.Equal(t, request.StatusCodeUnset, request.SpanStatusCode(&span))

		getter, ok := request.SpanOTELGetters(request.UnresolvedNames{})(attr.ErrorType)
		require.True(t, ok)
		assert.False(t, getter(&span).Valid(),
			"observation %d names an error type", observation)
	}
}

// The control. An observed response is untouched on every axis the fix moves.
func TestHTTPInfoEventToSpan_ObservedResponseIsUnchanged(t *testing.T) {
	event := clientRequestEvent()
	event.Status = 200
	event.RespLen = 227

	span, _, err := HTTPInfoEventToSpan(nil, event)
	require.NoError(t, err)

	assert.Equal(t, request.ResponseParsed, span.ResponseObservation)
	assert.Equal(t, 200, span.Status)
	assert.False(t, request.IgnoreMetrics(&span))
	assert.False(t, request.IgnoreDurations(&span))
	assert.Equal(t, request.StatusCodeUnset, request.SpanStatusCode(&span))
}

// parsedRelayResponse returns the request and response of a call whose response a
// large-buffer capture handed to userspace, which parsed it in full.
func parsedRelayResponse(t *testing.T) (*http.Request, *http.Response) {
	t.Helper()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /r HTTP/1.1\r\nHost: relay:9100\r\n\r\n")))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"status\":\"ok\"}\r\n")), req)
	require.NoError(t, err)

	return req, resp
}

// On the response-parsing path both sources exist at once, and the one that read the
// response wins. The kernel's classification is not an observation of the response, it
// is an observation of what a probe managed to do.
//
// event.RespLen disagrees with the parsed Content-Length on purpose: whichever source
// won is visible in the length as well as in the status.
func TestHTTPRequestResponseToSpan_ParsedResponseOutranksTheKernel(t *testing.T) {
	const parsedContentLength = 17

	for _, observation := range []uint8{
		bpfResponseReceived,
		bpfResponseSilent,
		bpfResponseUnread,
	} {
		event := clientRequestEvent()
		event.ResponseObservation = observation
		event.RespLen = parsedContentLength + 100

		req, resp := parsedRelayResponse(t)

		span := httpRequestResponseToSpan(nil, event, req, resp)

		assert.Equal(t, request.ResponseParsed, span.ResponseObservation,
			"observation %d: a response userspace parsed is a parsed response", observation)
		assert.Equal(t, 200, span.Status,
			"observation %d: the parsed status is reported", observation)
		assert.EqualValues(t, parsedContentLength, span.ResponseLength,
			"observation %d: the parsed length is reported, not event.RespLen", observation)
	}
}

// The one thing the kernel still knows better. Reading the response says nothing about
// when it arrived, and bpfResponseReceived timed the record at teardown.
func TestHTTPRequestResponseToSpan_ParsedResponseKeepsTheDurationVerdict(t *testing.T) {
	for _, tc := range []struct {
		observation uint8
		measured    bool
	}{
		{bpfResponseReceived, false},
		{bpfResponseSilent, true},
		{bpfResponseUnread, true},
		{bpfResponseParsed, true},
		// Nothing maps this value, and an unrecognized one withholds the duration.
		{^uint8(0), false},
	} {
		event := clientRequestEvent()
		event.ResponseObservation = tc.observation

		req, resp := parsedRelayResponse(t)

		span := httpRequestResponseToSpan(nil, event, req, resp)

		assert.Equal(t, tc.measured, !request.IgnoreDurations(&span),
			"observation %d: duration measured should be %v", tc.observation, tc.measured)
		assert.Equal(t, 200, span.Status,
			"observation %d: the duration verdict does not touch the status", tc.observation)
	}
}

// The two cases differ in one axis, whether the duration is a measurement, and agree on
// every other. Asserted together, so a regression that collapsed them cannot leave a
// passing assertion behind.
func TestHTTPInfoEventToSpan_ReceivedAndSilentDifferOnlyInTheirDuration(t *testing.T) {
	receivedEvent := clientRequestEvent()
	receivedEvent.ResponseObservation = bpfResponseReceived

	silentEvent := clientRequestEvent()
	silentEvent.ResponseObservation = bpfResponseSilent

	received, _, err := HTTPInfoEventToSpan(nil, receivedEvent)
	require.NoError(t, err)
	silent, _, err := HTTPInfoEventToSpan(nil, silentEvent)
	require.NoError(t, err)

	assert.NotEqual(t, request.ResponseParsed, received.ResponseObservation)
	assert.NotEqual(t, request.ResponseParsed, silent.ResponseObservation)
	assert.Equal(t, request.SpanStatusCode(&received), request.SpanStatusCode(&silent),
		"neither is judged, because neither was observed to succeed or to fail")
	assert.Equal(t, 0, received.Status)
	assert.Equal(t, 0, silent.Status)

	assert.True(t, request.IgnoreDurations(&received),
		"the peer answered and OBI lost the response, so the end time is not the request's")
	assert.False(t, request.IgnoreDurations(&silent),
		"nothing came back, so the close is the end of the request itself")
}

// The control on the encoding. Zero is a response that was read.
func TestHTTPInfoEventToSpan_ObservedEncodingIsUntouched(t *testing.T) {
	event := clientRequestEvent()
	event.ResponseObservation = bpfResponseParsed
	event.Status = 200

	span, _, err := HTTPInfoEventToSpan(nil, event)
	require.NoError(t, err)

	assert.Equal(t, request.ResponseParsed, span.ResponseObservation)
	assert.Equal(t, 200, span.Status)
	assert.False(t, request.IgnoreDurations(&span))
}
