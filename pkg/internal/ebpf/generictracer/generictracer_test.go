// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestBitPositionCalculation(t *testing.T) {
	for _, v := range [][4]uint32{
		{0, 1, 0, 1},
		{0, 2, 0, 2},
		{0, 65, 1, 1},
		{0, 66, 1, 2},
		{0, primeHash, 0, 0},
		{0, primeHash + 1, 0, 1},
	} {
		k := makeKey(v[0], v[1])
		segment, bit := pidSegmentBit(k)
		assert.Equal(t, segment, v[2])
		assert.Equal(t, bit, v[3])
	}
}

func makeKey(first, second uint32) uint64 {
	return (uint64(first) << 32) | uint64(second)
}

func TestConstantsTPParseSizeWhenLoopsSupported(t *testing.T) {
	tracer := New(nil, &obi.Config{
		EBPF: config.EBPFTracer{MaxRequestTPParseSizeKB: 27},
	}, nil)
	tracer.log = slog.Default()
	tracer.supportsBPFLoop = true

	constants := tracer.constants()
	value, ok := constants["bpf_max_request_tp_parse_size_kb"]
	require.True(t, ok)
	assert.Equal(t, uint32(27), value)
}

func TestConstantsTPParseSizeWhenLoopsUnsupported(t *testing.T) {
	tracer := New(nil, &obi.Config{
		EBPF: config.EBPFTracer{MaxRequestTPParseSizeKB: 27},
	}, nil)
	tracer.log = slog.Default()
	tracer.supportsBPFLoop = false

	constants := tracer.constants()
	value, ok := constants["bpf_max_request_tp_parse_size_kb"]
	require.True(t, ok)
	assert.Equal(t, uint32(0), value, "bpf_max_request_tp_parse_size_kb must be 0 on legacy kernels to prevent tail-calls into the dummy stub")
}
