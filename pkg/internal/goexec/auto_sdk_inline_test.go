// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedSDKFlagReadOffset(t *testing.T) {
	for _, test := range []struct {
		machine elf.Machine
		code    []byte
		offset  uint64
	}{
		{elf.EM_X86_64, []byte{0x90, 0x48, 0x8b, 0x0d, 0x18, 0xbe, 0x3c, 0, 0x80, 0x39, 0, 0x74, 0x11}, 8},
		{elf.EM_AARCH64, []byte{0x9b, 0x0b, 0, 0xb0, 0x62, 0xcb, 0x46, 0xf9, 0x42, 0, 0x40, 0x39, 0xe2, 0, 0, 0x36}, 8},
	} {
		assert.Equal(t, test.offset, embeddedSDKFlagReadOffset(test.machine, test.code))
		for index := range test.code {
			assert.Zero(t, embeddedSDKFlagReadOffset(test.machine, test.code[:index]))
		}
		code := append([]byte(nil), test.code...)
		code[test.offset] ^= 1
		assert.Zero(t, embeddedSDKFlagReadOffset(test.machine, code))
		assert.Zero(t, embeddedSDKFlagReadOffset(elf.EM_RISCV, test.code))
	}
	assert.Empty(t, embeddedSDKActivationAlias("unrelated.noopSpan.TracerProvider"))
	assert.Equal(t, "vendor/go.opentelemetry.io/otel/trace.noopSpan.tracerProvider",
		embeddedSDKActivationAlias("vendor/go.opentelemetry.io/otel/trace.(*nonRecordingSpan).TracerProvider"))
}
