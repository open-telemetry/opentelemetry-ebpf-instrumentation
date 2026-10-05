// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package largebuf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeShape_completeHeaders(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")
	p := ProbeShape(NewLargeBufferFrom(raw))
	assert.Equal(t, len(raw), p.Len)
	assert.True(t, p.StartsWithHTTP)
	assert.Equal(t, bytes.Index(raw, []byte("\r\n\r\n")), p.HeaderTerminatorOffset)
	assert.Equal(t, hex.EncodeToString(raw), p.Head64Hex)
}

func TestProbeShape_truncatedClusterClass(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\n00550")
	p := ProbeShape(NewLargeBufferFrom(raw))
	assert.Equal(t, -1, p.HeaderTerminatorOffset)
	assert.True(t, p.StartsWithHTTP)
	require.NotEmpty(t, p.Tail64Hex)
}
