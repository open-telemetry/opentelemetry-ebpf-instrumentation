// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package runtime

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	testSetObject     = uint64(0x1100)
	testSetString     = uint64(0x1200)
	testErrSetObject  = uint64(0x1400)
	testOtherFunction = uint64(0x1500)
	testNextFunction  = uint64(0x1600)
	x86RelativeBranch = 5
	x86CallOpcode     = 0xe8
	x86JumpOpcode     = 0xe9
	x86ReturnOpcode   = 0xc3
)

var (
	endBranch64       = []byte{0xf3, 0x0f, 0x1e, 0xfa}
	loadThreadStateRD = []byte{0x48, 0x8b, 0x78, 0x08} // mov rdi,[rax+8]
)

func relativeBranch(opcode byte, from, to uint64) []byte {
	encoded := []byte{opcode, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(encoded[1:], uint32(int32(to-(from+x86RelativeBranch))))
	return encoded
}

// setObjectStub mirrors the 3.13 shape: TLS lookup, tstate load, tail jump.
func setObjectStub(jumps ...uint64) []byte {
	code := append(append([]byte{}, endBranch64...), relativeBranch(x86CallOpcode, testSetObject+uint64(len(endBranch64)), testPLTAddress)...)
	code = append(code, loadThreadStateRD...)
	for _, target := range jumps {
		code = append(code, relativeBranch(x86JumpOpcode, testSetObject+uint64(len(code)), target)...)
	}
	return code
}

func setStringCaller(target uint64) []byte {
	code := relativeBranch(x86CallOpcode, testSetString, testPLTAddress)
	code = append(code, relativeBranch(x86CallOpcode, testSetString+x86RelativeBranch, target)...)
	return append(code, x86ReturnOpcode)
}

func deriveFromTestELF(t *testing.T, setObject, setString []byte) (uint64, error) {
	t.Helper()
	file := newProbeTestELF(t, map[uint64][]byte{testSetObject: setObject, testSetString: setString},
		[]uint64{testSetObject, testSetString, testErrSetObject, testOtherFunction, testNextFunction})
	return deriveErrSetObject(file,
		procs.Sym{Value: testSetObject, Len: uint64(len(setObject))},
		[]procs.Sym{{Value: testSetString, Len: uint64(len(setString))}})
}

func TestDeriveErrSetObject(t *testing.T) {
	offset, err := deriveFromTestELF(t, setObjectStub(testErrSetObject), setStringCaller(testErrSetObject))
	require.NoError(t, err)
	assert.Equal(t, testErrSetObject-testCodeBaseAddress+testCodeFileOffset, offset)

	// A tail jump to a PLT entry is an external helper, not the hidden setter.
	offset, err = deriveFromTestELF(t, setObjectStub(testPLTAddress, testErrSetObject), setStringCaller(testErrSetObject))
	require.NoError(t, err)
	assert.Equal(t, testErrSetObject-testCodeBaseAddress+testCodeFileOffset, offset)
}

func TestDeriveErrSetObjectRejectsUnconfirmedShapes(t *testing.T) {
	_, err := deriveFromTestELF(t, setObjectStub(testErrSetObject), setStringCaller(testOtherFunction))
	require.ErrorIs(t, err, errUnsupportedLayout, "PyErr_SetString must call the same target")

	_, err = deriveFromTestELF(t, setObjectStub(testErrSetObject, testOtherFunction), setStringCaller(testErrSetObject))
	require.ErrorIs(t, err, errUnsupportedLayout, "two local tail jumps are ambiguous")

	_, err = deriveFromTestELF(t, setObjectStub(), setStringCaller(testErrSetObject))
	require.ErrorIs(t, err, errUnsupportedLayout, "a stub without a tail jump")

	_, err = deriveFromTestELF(t, setObjectStub(testErrSetObject+1), setStringCaller(testErrSetObject+1))
	require.ErrorIs(t, err, errUnsupportedLayout, "the target must start a function")
}
