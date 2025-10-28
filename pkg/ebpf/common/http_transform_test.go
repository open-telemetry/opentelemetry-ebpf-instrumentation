// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

const bufSize = 256

func TestURL(t *testing.T) {
	event := BPFHTTPInfo{
		Buf: [bufSize]byte{'G', 'E', 'T', ' ', '/', 'p', 'a', 't', 'h', '?', 'q', 'u', 'e', 'r', 'y', '=', '1', '2', '3', '4', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1'},
	}
	assert.Equal(t, "/path?query=1234", httpURLFromBuf(event.Buf[:]))
	event = BPFHTTPInfo{}
	assert.Empty(t, httpURLFromBuf(event.Buf[:]))
}

func TestMethod(t *testing.T) {
	event := BPFHTTPInfo{
		Buf: [bufSize]byte{'G', 'E', 'T', ' ', '/', 'p', 'a', 't', 'h', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1'},
	}

	assert.Equal(t, "GET", httpMethodFromBuf(event.Buf[:]))
	event = BPFHTTPInfo{}
	assert.Empty(t, httpMethodFromBuf(event.Buf[:]))
}

func TestHostInfo(t *testing.T) {
	event := BPFHTTPInfo{
		ConnInfo: BpfConnectionInfoT{
			S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
			D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		},
	}

	source, target := (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()

	assert.Equal(t, "192.168.0.1", source)
	assert.Equal(t, "8.8.8.8", target)

	event = BPFHTTPInfo{
		ConnInfo: BpfConnectionInfoT{
			S_addr: [16]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
			D_addr: [16]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		},
	}

	source, target = (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()

	assert.Equal(t, "100::ffff:c0a8:1", source)
	assert.Equal(t, "100::ffff:808:808", target)

	event = BPFHTTPInfo{
		ConnInfo: BpfConnectionInfoT{},
	}

	source, target = (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()

	assert.Empty(t, source)
	assert.Empty(t, target)
}

func TestCstr(t *testing.T) {
	testCases := []struct {
		input    []uint8
		expected string
	}{
		{[]uint8{72, 101, 108, 108, 111, 0}, "Hello"},
		{[]uint8{87, 111, 114, 108, 100, 0}, "World"},
		{[]uint8{72, 101, 108, 108, 111}, "Hello"},
		{[]uint8{87, 111, 114, 108, 100}, "World"},
		{[]uint8{}, ""},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.expected, cstr(tc.input))
	}
}

func TestToRequestTrace(t *testing.T) {
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

	var record BPFHTTPInfo
	record.Type = 1
	record.ReqMonotimeNs = 123450
	record.StartMonotimeNs = 123456
	record.EndMonotimeNs = 789012
	record.Status = 200
	record.ConnInfo.D_port = 1
	record.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	record.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}
	copy(record.Buf[:], "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &record)
	require.NoError(t, err)

	result, _, err := ReadHTTPInfoIntoSpan(nil, &ringbuf.Record{RawSample: buf.Bytes()}, &fltr)
	require.NoError(t, err)

	expected := request.Span{
		Host:         "8.8.8.8",
		Peer:         "192.168.0.1",
		Path:         "/hello",
		Method:       "GET",
		Status:       200,
		Type:         request.EventTypeHTTP,
		RequestStart: 123450,
		Start:        123456,
		End:          789012,
		HostPort:     1,
		Service:      svc.Attrs{},
		Statement:    "http;",
	}
	assert.Equal(t, expected, result)
}

func TestToRequestTraceNoConnection(t *testing.T) {
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

	var record BPFHTTPInfo
	record.Type = 1
	record.ReqMonotimeNs = 123450
	record.StartMonotimeNs = 123456
	record.EndMonotimeNs = 789012
	record.Status = 200
	record.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	record.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}
	copy(record.Buf[:], "GET /hello HTTP/1.1\r\nHost: localhost:7033\r\n\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n")

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &record)
	require.NoError(t, err)

	result, _, err := ReadHTTPInfoIntoSpan(nil, &ringbuf.Record{RawSample: buf.Bytes()}, &fltr)
	require.NoError(t, err)

	// change the expected port just before testing
	expected := request.Span{
		Host:         "localhost",
		Peer:         "",
		Path:         "/hello",
		Method:       "GET",
		Type:         request.EventTypeHTTP,
		Start:        123456,
		RequestStart: 123450,
		End:          789012,
		Status:       200,
		HostPort:     7033,
		Service:      svc.Attrs{},
		Statement:    "http;localhost",
	}
	assert.Equal(t, expected, result)
}

func TestToRequestTrace_BadHost(t *testing.T) {
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

	var record BPFHTTPInfo
	record.Type = 1
	record.ReqMonotimeNs = 123450
	record.StartMonotimeNs = 123456
	record.EndMonotimeNs = 789012
	record.Status = 200
	record.ConnInfo.D_port = 0
	record.ConnInfo.S_port = 0
	record.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	record.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}
	copy(record.Buf[:], "GET /hello HTTP/1.1\r\nHost: example.c")

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &record)
	require.NoError(t, err)

	result, _, err := ReadHTTPInfoIntoSpan(nil, &ringbuf.Record{RawSample: buf.Bytes()}, &fltr)
	require.NoError(t, err)

	expected := request.Span{
		Host:         "",
		Peer:         "",
		Path:         "/hello",
		Method:       "GET",
		Status:       200,
		Type:         request.EventTypeHTTP,
		RequestStart: 123450,
		Start:        123456,
		End:          789012,
		HostPort:     0,
		Service:      svc.Attrs{},
		Statement:    "http;example.c",
	}
	assert.Equal(t, expected, result)

	s, p := httpHostFromBuf(record.Buf[:])
	assert.Equal(t, "example.c", s)
	assert.Equal(t, -1, p)

	var record1 BPFHTTPInfo
	copy(record1.Buf[:], "GET /hello HTTP/1.1\r\nHost: example.c:23")

	s, p = httpHostFromBuf(record1.Buf[:])
	assert.Equal(t, "example.c", s)
	assert.Equal(t, 23, p)

	var record2 BPFHTTPInfo
	copy(record2.Buf[:], "GET /hello HTTP/1.1\r\nHost: ")

	s, p = httpHostFromBuf(record2.Buf[:])
	assert.Empty(t, s)
	assert.Equal(t, -1, p)

	var record3 BPFHTTPInfo
	copy(record3.Buf[:], "GET /hello HTTP/1.1\r\nHost")

	s, p = httpHostFromBuf(record3.Buf[:])
	assert.Empty(t, s)
	assert.Equal(t, -1, p)
}

func TestHTTPInfoParsing(t *testing.T) {
	t.Run("Test basic parsing", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "/users", "127.0.0.1", "127.0.0.2", 12345, 8080, 200, 5)
		s := httpInfoToSpanLegacy(&tr)
		assertMatchesInfo(t, &s, "POST", "/users", "127.0.0.1", "127.0.0.2", 8080, 200, 5)
	})

	t.Run("Test empty URL", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "", "127.0.0.1", "127.0.0.2", 12345, 8080, 200, 5)
		s := httpInfoToSpanLegacy(&tr)
		assertMatchesInfo(t, &s, "POST", "", "127.0.0.1", "127.0.0.2", 8080, 200, 5)
	})

	t.Run("Test parsing with URL parameters", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "/users?query=1234", "127.0.0.1", "127.0.0.2", 12345, 8080, 200, 5)
		s := httpInfoToSpanLegacy(&tr)
		assertMatchesInfo(t, &s, "POST", "/users", "127.0.0.1", "127.0.0.2", 8080, 200, 5)
	})
}

func TestMethodURLParsing(t *testing.T) {
	for _, s := range []string{
		"GET /test ",
		"GET /test\r\n",
		"GET /test\r",
		"GET /test\n",
		"GET /test",
		"GET /test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test/",
	} {
		i := makeBPFInfoWithBuf([]uint8(s))
		assert.NotEmpty(t, httpURLFromBuf(i.Buf[:]), "-"+s+"-")
		assert.NotEmpty(t, httpMethodFromBuf(i.Buf[:]), "-"+s+"-")
		assert.True(t, strings.HasPrefix(httpURLFromBuf(i.Buf[:]), "/test"))
	}

	i := makeBPFInfoWithBuf([]uint8("GET "))
	assert.NotEmpty(t, httpMethodFromBuf(i.Buf[:]))
	assert.Empty(t, httpURLFromBuf(i.Buf[:]))

	i = makeBPFInfoWithBuf([]uint8(""))
	assert.Empty(t, httpMethodFromBuf(i.Buf[:]))
	assert.Empty(t, httpURLFromBuf(i.Buf[:]))

	i = makeBPFInfoWithBuf([]uint8("POST"))
	assert.Empty(t, httpMethodFromBuf(i.Buf[:]))
	assert.Empty(t, httpURLFromBuf(i.Buf[:]))
}

func makeHTTPInfo(method, path, peer, host string, peerPort, hostPort uint32, status uint16, durationMs uint64) HTTPInfo {
	bpfInfo := BPFHTTPInfo{
		Type:            1,
		Status:          status,
		ReqMonotimeNs:   durationMs * 1000000,
		StartMonotimeNs: durationMs * 1000000,
		EndMonotimeNs:   durationMs * 2 * 1000000,
	}
	i := HTTPInfo{
		BPFHTTPInfo: bpfInfo,
		Method:      method,
		Peer:        peer,
		URL:         path,
		Host:        host,
	}

	i.ConnInfo.D_port = uint16(hostPort)
	i.ConnInfo.S_port = uint16(peerPort)

	return i
}

func assertMatchesInfo(t *testing.T, span *request.Span, method, path, peer, host string, hostPort int, status int, durationMs uint64) {
	assert.Equal(t, method, span.Method)
	assert.Equal(t, path, span.Path)
	assert.Equal(t, host, span.Host)
	assert.Equal(t, hostPort, span.HostPort)
	assert.Equal(t, peer, span.Peer)
	assert.Equal(t, status, span.Status)
	assert.Equal(t, int64(durationMs*1000000), span.End-span.Start)
	assert.Equal(t, int64(durationMs*1000000), span.End-span.RequestStart)
}

func makeBPFInfoWithBuf(buf []uint8) BPFHTTPInfo {
	bpfInfo := BPFHTTPInfo{}
	copy(bpfInfo.Buf[:], buf)

	return bpfInfo
}
