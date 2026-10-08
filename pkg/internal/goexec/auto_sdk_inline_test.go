// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedSDKFlagReadOffset(t *testing.T) {
	for _, test := range []struct {
		machine        elf.Machine
		code           []byte
		invalidOffsets map[int]string
	}{
		{elf.EM_X86_64, []byte{
			0x90,                                     // NOP: unrelated instruction before the match.
			0x48, 0x8b, 0x0d, 0x18, 0xbe, 0x3c, 0x00, // MOV RCX, [RIP+0x3cbe18]: load the flag pointer.
			0x80, 0x39, 0x00, // CMP byte [RCX], 0: read the flag at offset 8.
			0x74, 0x11, // JE: branch when the flag is false.
		}, map[int]string{
			3: "pointer load uses unsupported addressing", 8: "flag read is wider than one byte",
			9: "flag read uses RAX instead of RCX", 11: "branch condition is inverted",
		}},
		{elf.EM_AARCH64, []byte{
			0x9b, 0x0b, 0x00, 0xb0, // ADRP X27: locate the page containing the flag pointer.
			0x62, 0xcb, 0x46, 0xf9, // LDR X2, [X27, #3472]: load the flag pointer.
			0x42, 0x00, 0x40, 0x39, // LDRB W2, [X2]: read the flag at offset 8.
			0xe2, 0x00, 0x00, 0x36, // TBZ W2, #0: branch when the flag is false.
		}, map[int]string{
			4: "pointer is loaded into X3", 8: "flag is read into W3", 12: "branch tests W3",
		}},
	} {
		assert.Equal(t, uint64(8), embeddedSDKFlagReadOffset(test.machine, test.code))
		for index := range test.code {
			assert.Zero(t, embeddedSDKFlagReadOffset(test.machine, test.code[:index]))
		}
		for index, reason := range test.invalidOffsets {
			code := append(bytes.Clone(test.code), 0, 0, 0) // Keep a widened CMP instruction decodable.
			code[index] ^= 1
			assert.Zero(t, embeddedSDKFlagReadOffset(test.machine, code), reason)
		}
		assert.Zero(t, embeddedSDKFlagReadOffset(elf.EM_RISCV, test.code))
	}
	assert.Empty(t, embeddedSDKActivationAlias("unrelated.noopSpan.TracerProvider"))
	assert.Equal(t, "vendor/go.opentelemetry.io/otel/trace.noopSpan.tracerProvider",
		embeddedSDKActivationAlias("vendor/go.opentelemetry.io/otel/trace.(*nonRecordingSpan).TracerProvider"))
}
