// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
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

func TestPythonAsyncioModule(t *testing.T) {
	for _, tc := range []struct {
		path   string
		module string
	}{
		{
			path:   "/usr/local/lib/python3.9/lib-dynload/_asyncio.cpython-39-x86_64-linux-gnu.so",
			module: "python3.9/lib-dynload/_asyncio",
		},
		{
			path:   "/opt/python3.11/lib-dynload/_asyncio.cpython-311-aarch64-linux-gnu.so",
			module: "python3.11/lib-dynload/_asyncio",
		},
		{
			path:   "/usr/lib/python3.15/lib-dynload/_asyncio.cpython-315-x86_64-linux-gnu.so",
			module: "python3.15/lib-dynload/_asyncio",
		},
		{
			path:   "/usr/lib/libpython3.14.so.1.0",
			module: "",
		},
		{
			path:   "/usr/lib/python3.14/site-packages/foo.so",
			module: "",
		},
	} {
		assert.Equal(t, tc.module, pythonAsyncioModule(tc.path), tc.path)
	}
}

func TestPythonAsyncioTaskStepStart(t *testing.T) {
	legacyProbe := &ebpf.Program{}
	defaultProbe := &ebpf.Program{}

	assert.Equal(t, legacyProbe, pythonAsyncioTaskStepStart("python3.9/lib-dynload/_asyncio", legacyProbe, defaultProbe))
	assert.Equal(t, legacyProbe, pythonAsyncioTaskStepStart("python3.10/lib-dynload/_asyncio", legacyProbe, defaultProbe))
	assert.Equal(t, legacyProbe, pythonAsyncioTaskStepStart("python3.11/lib-dynload/_asyncio", legacyProbe, defaultProbe))
	assert.Equal(t, defaultProbe, pythonAsyncioTaskStepStart("python3.12/lib-dynload/_asyncio", legacyProbe, defaultProbe))
	assert.Equal(t, defaultProbe, pythonAsyncioTaskStepStart("python3.15/lib-dynload/_asyncio", legacyProbe, defaultProbe))
	assert.Equal(t, defaultProbe, pythonAsyncioTaskStepStart("", legacyProbe, defaultProbe))
}
