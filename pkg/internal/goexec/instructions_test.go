// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

package goexec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// singleRetProg is a real amd64 function body used to exercise FindReturnOffsets.
// It contains exactly one RET (c3) at byte offset 0x46.
//
// Disassembly sketch:
//
//	0x00  f3 0f 1e fa           ENDBR64
//	0x04  f3 0f 1e fb           ENDBR32
//	0x08  55                    PUSH RBP
//	0x09  48 89 e5              MOV RBP, RSP
//	0x0c  48 83 ec 10           SUB RSP, 0x10
//	0x10  64 48 8b 04 25 …      MOV RAX, fs:[0x28]  (stack canary)
//	…
//	0x43  75 3c                 JNZ +0x3c
//	0x45  c9                    LEAVE
//	0x46  c3                    RET          ← the only return
//	0x47  ff 15 …               CALL [RIP+…]  (error path, never falls through)
//	…
var singleRetProg = []uint8{
	0xf3, 0x0f, 0x1e, 0xfa, // 0x00 ENDBR64
	0xf3, 0x0f, 0x1e, 0xfb, // 0x04 ENDBR32
	0x55,             // 0x08 PUSH RBP
	0x48, 0x89, 0xe5, // 0x09 MOV RBP, RSP
	0x48, 0x83, 0xec, 0x10, // 0x0c SUB RSP, 0x10
	0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00,
	0x00, 0x00, // 0x10 MOV RAX, fs:[0x28]
	0x48, 0x89, 0x45, 0xf8, // 0x19 MOV [RBP-8], RAX
	0x31, 0xc0, // 0x1d XOR EAX, EAX
	0x85, 0xd2, // 0x1f TEST EDX, EDX
	0x78, 0x24, // 0x21 JS +0x24
	0x48, 0x8d, 0x4d, 0xf0, // 0x23 LEA RCX, [RBP-0x10]
	0x48, 0x63, 0xd2, // 0x27 MOVSXD RDX, EDX
	0xe8, 0x25, 0xfd, 0xff, 0xff, // 0x2a CALL -0x2db
	0x85, 0xc0, // 0x2f TEST EAX, EAX
	0x7e, 0x03, // 0x31 JLE +3
	0x8b, 0x45, 0xf0, // 0x33 MOV EAX, [RBP-0x10]
	0x48, 0x8b, 0x55, 0xf8, // 0x36 MOV RDX, [RBP-8]
	0x64, 0x48, 0x2b, 0x14, 0x25, 0x28, 0x00,
	0x00, 0x00, // 0x3a SUB RDX, fs:[0x28]
	0x75, 0x3c, // 0x43 JNZ +0x3c
	0xc9,                               // 0x45 LEAVE
	0xc3,                               // 0x46 RET  ← only return in this buffer
	0xff, 0x15, 0x2f, 0x1a, 0x0b, 0x00, // 0x47 CALL [RIP+…]
	0x48, 0x8d, 0x15, 0x28, 0xfd, 0x08, 0x00,
	0xbe, 0x18, 0x09, 0x00, 0x00,
	0x48, 0x8d, 0x3d, 0x82, 0x4f, 0x08, 0x00,
	0xff, 0x15, 0x4e, 0x1d, 0x0b, 0x00,
	0x31, 0xc0,
	0x31, 0xd2,
	0xbe, 0x0f, 0x01, 0x00, 0x00,
	0xbf, 0x14, 0x00, 0x00, 0x00,
	0xff, 0x15, 0x72, 0x1c, 0x0b, 0x00,
	0xb8, 0xff, 0xff, 0xff, 0xff,
	0xeb, 0xb5,
	0xff, 0x15, 0xb5, 0x21, 0x0b, 0x00,
}

// TestFindReturnOffsets_SingleRet checks that the exact set of return offsets
// found in singleRetProg is {0x46} — no more, no fewer.
func TestFindReturnOffsets_SingleRet(t *testing.T) {
	offsets, err := FindReturnOffsets(0, singleRetProg)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x46}, offsets)
}

// TestFindReturnOffsets_BaseOffset verifies that every reported offset equals
// baseOffset + the instruction's position within data.
func TestFindReturnOffsets_BaseOffset(t *testing.T) {
	const base = uint64(0x1000)
	offsets, err := FindReturnOffsets(base, singleRetProg)
	require.NoError(t, err)
	require.Equal(t, []uint64{base + 0x46}, offsets)
}

// TestFindReturnOffsets_Empty verifies that an empty input produces no offsets
// and no error.
func TestFindReturnOffsets_Empty(t *testing.T) {
	offsets, err := FindReturnOffsets(0, []byte{})
	require.NoError(t, err)
	require.Empty(t, offsets)
}

// TestFindReturnOffsets_NoRet verifies that a buffer with no RET instruction
// produces an empty result.
//
//	0x00  55        PUSH RBP
//	0x01  48 89 e5  MOV RBP, RSP
//	0x04  5d        POP RBP
func TestFindReturnOffsets_NoRet(t *testing.T) {
	noRet := []byte{
		0x55,             // PUSH RBP
		0x48, 0x89, 0xe5, // MOV RBP, RSP
		0x5d, // POP RBP
	}
	offsets, err := FindReturnOffsets(0, noRet)
	require.NoError(t, err)
	require.Empty(t, offsets)
}

// TestFindReturnOffsets_MultipleRets checks that all RET instructions are
// reported when more than one is present.  Equal (not ElementsMatch) is correct
// here: the implementation scans left-to-right and appends in order, so the
// returned slice is guaranteed to be in ascending offset order.
//
//	0x00  90  NOP
//	0x01  c3  RET
//	0x02  90  NOP
//	0x03  c3  RET
func TestFindReturnOffsets_MultipleRets(t *testing.T) {
	multiRet := []byte{
		0x90, // NOP
		0xc3, // RET  → offset 0x01
		0x90, // NOP
		0xc3, // RET  → offset 0x03
	}
	offsets, err := FindReturnOffsets(0, multiRet)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x01, 0x03}, offsets)
}

// TestFindReturnOffsets_RetWithImmediate verifies that the far-return-with-immediate
// variant (c2 imm16) is recognized as a RET.  Both c3 and c2 decode to
// x86asm.RET, so the function handles them identically.
//
//	0x00  c2 10 00  RET 0x10
func TestFindReturnOffsets_RetWithImmediate(t *testing.T) {
	buf := []byte{0xc2, 0x10, 0x00} // RET 0x10
	offsets, err := FindReturnOffsets(0, buf)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x00}, offsets)
}

// TestFindReturnOffsets_TruncatedInstruction verifies that a buffer ending with
// an incomplete instruction sequence is handled without error.  The underlying
// x86asm decoder does not return errors for truncated encodings — it emits a
// synthetic Op(0) instruction of length 1 and advances past the byte — so
// FindReturnOffsets silently skips unrecognized bytes rather than aborting.
//
//	0x00  90        NOP   (valid)
//	0x01  48 8b     REX.W + MOV opcode, ModRM byte absent  (truncated)
func TestFindReturnOffsets_TruncatedInstruction(t *testing.T) {
	buf := []byte{
		0x90,       // NOP
		0x48, 0x8b, // incomplete MOV r64,r/m64 — no ModRM byte
	}
	offsets, err := FindReturnOffsets(0, buf)
	require.NoError(t, err)
	require.Empty(t, offsets)
}
