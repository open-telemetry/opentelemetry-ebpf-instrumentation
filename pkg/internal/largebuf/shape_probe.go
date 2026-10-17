// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package largebuf

import (
	"bytes"
	"encoding/hex"
)

// ShapeProbe summarizes buffer layout for DEBUG when HTTP parsing fails (hex head/tail only).
type ShapeProbe struct {
	Len                    int
	HeaderTerminatorOffset int
	StartsWithHTTP         bool
	Head64Hex              string
	Tail64Hex              string
}

// ProbeShape inspects contiguous buffer bytes (e.g. HTTP response large buffer).
func ProbeShape(buf *LargeBuffer) ShapeProbe {
	if buf == nil || buf.IsEmpty() {
		return ShapeProbe{HeaderTerminatorOffset: -1}
	}
	raw := buf.UnsafeView()
	n := len(raw)
	return ShapeProbe{
		Len:                    n,
		HeaderTerminatorOffset: bytes.Index(raw, []byte("\r\n\r\n")),
		StartsWithHTTP:         bytes.HasPrefix(raw, []byte("HTTP/")),
		Head64Hex:              hex.EncodeToString(slicePrefix(raw, 64)),
		Tail64Hex:              hex.EncodeToString(sliceSuffix(raw, 64)),
	}
}

func slicePrefix(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func sliceSuffix(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
