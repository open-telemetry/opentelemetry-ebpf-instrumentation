// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPProtoVersionFromRequestLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want ProtoVersion
	}{
		{"1.1", "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n", ProtoVersionHTTP11},
		{"1.0", "GET /hello HTTP/1.0\r\n\r\n", ProtoVersionHTTP10},
		{"2", "GET /hello HTTP/2\r\n\r\n", ProtoVersionHTTP2},
		{"2.0", "GET /hello HTTP/2.0\r\n\r\n", ProtoVersionHTTP2},
		{"no trailing CRLF", "GET /hello HTTP/1.1", ProtoVersionHTTP11},
		{"NUL terminated", "GET /hello HTTP/1.1\x00garbage", ProtoVersionHTTP11},
		{"version-like path", "GET /redirect?to=%20HTTP/9.9 HTTP/1.1\r\n", ProtoVersionHTTP11},
		{"unknown version", "GET /hello HTTP/4.2\r\n", ProtoVersionUnknown},
		{"not a request line", "\x16\x03\x01\x02\x00", ProtoVersionUnknown},
		{"truncated before the version", "GET /hello", ProtoVersionUnknown},
		{"empty", "", ProtoVersionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HTTPProtoVersionFromRequestLine([]byte(tc.line)))
		})
	}
}

func TestProtoVersionString(t *testing.T) {
	assert.Equal(t, "1.0", ProtoVersionHTTP10.String())
	assert.Equal(t, "1.1", ProtoVersionHTTP11.String())
	assert.Equal(t, "2", ProtoVersionHTTP2.String())
	assert.Empty(t, ProtoVersionUnknown.String())
	assert.Empty(t, ProtoVersion(200).String())
}

func TestHTTPProtoVersion(t *testing.T) {
	for _, tc := range []struct {
		major, minor int
		expected     ProtoVersion
	}{
		{1, 0, ProtoVersionHTTP10},
		{1, 1, ProtoVersionHTTP11},
		{2, 0, ProtoVersionHTTP2},
		{3, 0, ProtoVersionUnknown},
		{1, 2, ProtoVersionUnknown},
		{0, 0, ProtoVersionUnknown},
	} {
		assert.Equal(t, tc.expected, HTTPProtoVersion(tc.major, tc.minor),
			"HTTP/%d.%d", tc.major, tc.minor)
	}
}
