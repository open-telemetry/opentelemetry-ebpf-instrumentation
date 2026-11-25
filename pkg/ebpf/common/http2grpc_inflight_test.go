// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestGRPCInflightSpan(t *testing.T) {
	const (
		connID   = uint64(7)
		streamID = uint32(5)
		now      = 90 * time.Second
	)

	newInfo := func() *BPFHTTP2Info {
		info := &BPFHTTP2Info{
			Type:            uint8(request.EventTypeHTTP),
			NewConnId:       connID,
			StreamId:        streamID,
			StartMonotimeNs: uint64(10 * time.Second),
			EndMonotimeNs:   0,
			ConnInfo:        BpfConnectionInfoT{S_port: 40000, D_port: 50051},
		}
		info.Tp.TraceId[0] = 1
		info.Tp.SpanId[0] = 2
		return info
	}
	setup := func(mutate func(*h2Connection)) *EBPFParseContext {
		parseCtx := NewEBPFParseContext(nil, nil, nil)
		h2c := getOrInitH2Conn(parseCtx.h2c, connID)
		h2c.protocol = GRPC
		h2c.streams[streamID] = &h2StreamMeta{
			requestSeen: true,
			requestOK:   true,
			request:     h2RequestMeta{method: "POST", path: "/pkg.Svc/Block", grpc: true},
		}
		if mutate != nil {
			mutate(h2c)
		}
		return parseCtx
	}

	t.Run("open stream without response becomes an in-flight span", func(t *testing.T) {
		span, ok := GRPCInflightSpan(setup(nil), newInfo(), now)
		require.True(t, ok)
		assert.Equal(t, request.EventTypeGRPC, span.Type)
		assert.Equal(t, GRPCInflightStatus, span.Status)
		assert.Equal(t, "/pkg.Svc/Block", span.Path)
		assert.Equal(t, "pkg.Svc/Block", span.TraceName())
		assert.Equal(t, int64(10*time.Second), span.Start)
		assert.Equal(t, int64(now), span.End)
		assert.Equal(t, byte(1), span.TraceID[0])
		assert.Equal(t, byte(2), span.SpanID[0])
	})

	skipped := map[string]struct {
		mutate func(*h2Connection)
		info   func(*BPFHTTP2Info)
	}{
		"response headers already seen": {mutate: func(c *h2Connection) { c.streams[streamID].responseSeen = true }},
		"stream already completed":      {mutate: func(c *h2Connection) { c.completed[streamID] = struct{}{} }},
		"no cached stream":              {mutate: func(c *h2Connection) { delete(c.streams, streamID) }},
		"request metadata unreliable":   {mutate: func(c *h2Connection) { c.streams[streamID].requestOK = false }},
		"not a gRPC connection":         {mutate: func(c *h2Connection) { c.protocol = HTTP2 }},
		"path is not a gRPC method":     {mutate: func(c *h2Connection) { c.streams[streamID].request.path = "*" }},
		"client stream":                 {info: func(i *BPFHTTP2Info) { i.Type = uint8(request.EventTypeHTTPClient) }},
		"connection stream":             {info: func(i *BPFHTTP2Info) { i.StreamId = 0 }},
	}
	for name, tc := range skipped {
		t.Run("skips "+name, func(t *testing.T) {
			info := newInfo()
			if tc.info != nil {
				tc.info(info)
			}
			_, ok := GRPCInflightSpan(setup(tc.mutate), info, now)
			assert.False(t, ok)
		})
	}

	t.Run("unknown connection is not created", func(t *testing.T) {
		parseCtx := NewEBPFParseContext(nil, nil, nil)
		_, ok := GRPCInflightSpan(parseCtx, newInfo(), now)
		assert.False(t, ok)
		assert.Zero(t, parseCtx.h2c.Len())
	})
}
