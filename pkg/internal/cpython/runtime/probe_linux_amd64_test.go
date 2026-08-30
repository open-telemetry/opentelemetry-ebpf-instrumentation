// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package runtime

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/arch/x86/x86asm"
)

const (
	testCodeBaseAddress    = uint64(0x1000)
	testCodeFileOffset     = uint64(0x100)
	testCodeSegmentSize    = uint64(0x1000)
	testFrameHeaderAddress = uint64(0x4000)
	testPLTAddress         = uint64(0x1e00)
)

func TestSelectPrivateCollectorSymbol(t *testing.T) {
	function := func(name string, value uint64) elf.Symbol {
		return elf.Symbol{Name: name, Info: byte(elf.STT_FUNC), Section: 1, Value: value}
	}

	t.Run("exact", func(t *testing.T) {
		address, err := selectPrivateCollectorSymbol([]elf.Symbol{function("gc_collect_main", 0x2000)})
		require.NoError(t, err)
		assert.Equal(t, uint64(0x2000), address)
	})

	t.Run("supported variants", func(t *testing.T) {
		address, err := selectPrivateCollectorSymbol([]elf.Symbol{
			function("gc_collect_main.lto_priv.0", 0x3000),
			function("gc_collect_main.lto_priv.0.cold", 0x1000),
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(0x3000), address)
	})

	t.Run("duplicate tables", func(t *testing.T) {
		symbol := function("collect_with_callback", 0x4000)
		address, err := selectPrivateCollectorSymbol([]elf.Symbol{symbol}, []elf.Symbol{symbol})
		require.NoError(t, err)
		assert.Equal(t, uint64(0x4000), address)
	})

	t.Run("missing", func(t *testing.T) {
		_, err := selectPrivateCollectorSymbol([]elf.Symbol{function("unrelated", 0x5000)})
		require.ErrorIs(t, err, errUnsupportedLayout)
	})

	t.Run("ambiguous", func(t *testing.T) {
		_, err := selectPrivateCollectorSymbol([]elf.Symbol{
			function("gc_collect_main", 0x6000),
			function("gc_collect_internal", 0x7000),
		})
		require.ErrorIs(t, err, errUnsupportedLayout)
	})
}

func TestRepeatedCallCollector(t *testing.T) {
	const callback, collector = uint64(0x1200), uint64(0x1500)

	target, found, err := repeatedCallCollector([]uint64{callback, collector, callback})
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, collector, target)

	_, found, err = repeatedCallCollector([]uint64{callback, collector, 0x1300})
	require.NoError(t, err)
	require.False(t, found)

	_, _, err = repeatedCallCollector([]uint64{
		callback, collector, callback,
		0x1400, 0x1600, 0x1400,
	})
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestRelativeInstructionTargetFromDisplacement(t *testing.T) {
	decoded := decodedInstruction{
		address: 0x2780c6,
		inst: x86asm.Inst{
			Len:  5,
			Args: x86asm.Args{x86asm.Rel(-0x7c2fb)},
		},
	}

	target, err := relativeInstructionTarget(decoded)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x1fbdd0), target)

	_, err = relativeInstructionTarget(decodedInstruction{inst: x86asm.Inst{
		Len: 2, Args: x86asm.Args{x86asm.RAX},
	}})
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestBoundedFunctionSize(t *testing.T) {
	size, err := boundedFunctionSize([]uint64{0x278080, 0x278110}, 0x278080)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x90), size)

	_, err = boundedFunctionSize([]uint64{0x278080}, 0x278080)
	require.ErrorIs(t, err, errUnsupportedLayout)

	_, err = boundedFunctionSize([]uint64{0x1000, 0x1000 + maximumPythonFunctionSize + 1}, 0x1000)
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestPythonFunctionStarts(t *testing.T) {
	want := []uint64{0x1100, 0x1200, 0x1500}
	file := newProbeTestELF(t, nil, []uint64{want[2], want[0], want[1]})

	starts, err := pythonFunctionStarts(file)
	require.NoError(t, err)
	assert.Equal(t, want, starts)
}

func TestPythonFunctionStartsRejectsMalformedTables(t *testing.T) {
	tests := map[string][]byte{}
	unsupported := functionStartTable([]uint64{0x1100})
	unsupported[0] = 2
	tests["unsupported encoding"] = unsupported
	truncated := functionStartTable([]uint64{0x1100})
	tests["truncated entry"] = truncated[:len(truncated)-1]
	tests["duplicate start"] = functionStartTable([]uint64{0x1100, 0x1100})

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			file := newProbeTestELF(t, nil, []uint64{0x1100})
			section := file.Section(".eh_frame_hdr")
			section.Size = uint64(len(data))
			section.ReaderAt = bytes.NewReader(data)

			_, err := pythonFunctionStarts(file)
			require.ErrorIs(t, err, errUnsupportedLayout)
		})
	}
}

func TestDirectCallsFiltersPLTAndPreservesOrder(t *testing.T) {
	const root = uint64(0x1100)
	body := newTestMachineCode(root)
	body.call(0x1500)
	body.call(testPLTAddress)
	body.call(0x1520)
	body.emit(0xc3)
	file := newProbeTestELF(t, map[uint64][]byte{root: body.data}, nil)

	calls, err := directCalls(file, root, uint64(len(body.data)))
	require.NoError(t, err)
	assert.Equal(t, []uint64{0x1500, 0x1520}, calls)
}

func TestDirectCallsRejectsIndirectCall(t *testing.T) {
	const root = uint64(0x1100)
	body := []byte{0xff, 0xd0, 0xc3}
	file := newProbeTestELF(t, map[uint64][]byte{root: body}, nil)

	_, err := directCalls(file, root, uint64(len(body)))
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestDecodePythonInstructionEndBranch64(t *testing.T) {
	const address = uint64(0x1100)
	file := newProbeTestELF(t, map[uint64][]byte{
		address: endBranch64Encoding[:],
	}, nil)

	decoded, err := decodePythonInstruction(file, address, address+uint64(len(endBranch64Encoding)))
	require.NoError(t, err)
	assert.Equal(t, len(endBranch64Encoding), decoded.inst.Len)
	assert.Equal(t, x86asm.NOP, decoded.inst.Op)
}

func TestValidateCollectorTarget(t *testing.T) {
	file := newProbeTestELF(t, nil, nil)
	starts := []uint64{0x1500, testPLTAddress}

	require.NoError(t, validateCollectorTarget(file, starts, 0x1500))
	require.ErrorIs(t, validateCollectorTarget(file, starts, 0x1520), errUnsupportedLayout)
	require.ErrorIs(t, validateCollectorTarget(file, starts, testPLTAddress), errUnsupportedLayout)
}

func TestCollectorFromRepeatedCallShape(t *testing.T) {
	const root, wrapper = uint64(0x1100), uint64(0x1200)
	const callback, collector = uint64(0x1400), uint64(0x1500)

	t.Run("root", func(t *testing.T) {
		body := newTestMachineCode(root)
		body.call(callback)
		body.call(collector)
		body.call(callback)
		body.emit(0xc3)
		file := newProbeTestELF(t, map[uint64][]byte{root: body.data}, []uint64{collector, 0x1600})

		target, err := collectorFromRepeatedCallShape(file, []uint64{collector, 0x1600}, root, uint64(len(body.data)))
		require.NoError(t, err)
		assert.Equal(t, collector, target)
	})

	t.Run("one wrapper level", func(t *testing.T) {
		rootBody := newTestMachineCode(root)
		rootBody.call(wrapper)
		rootBody.emit(0xc3)
		wrapperBody := newTestMachineCode(wrapper)
		wrapperBody.call(callback)
		wrapperBody.call(collector)
		wrapperBody.call(callback)
		wrapperBody.emit(0xc3)
		starts := []uint64{wrapper, wrapper + uint64(len(wrapperBody.data)), collector, 0x1600}
		file := newProbeTestELF(t, map[uint64][]byte{
			root: rootBody.data, wrapper: wrapperBody.data,
		}, starts)

		target, err := collectorFromRepeatedCallShape(file, starts, root, uint64(len(rootBody.data)))
		require.NoError(t, err)
		assert.Equal(t, collector, target)
	})
}

func TestCollectorFromRepeatedCallShapeSkipsIndirectCallee(t *testing.T) {
	const root, wrapper, unrelated = uint64(0x1100), uint64(0x1200), uint64(0x1300)
	const callback, collector = uint64(0x1400), uint64(0x1500)
	rootBody := newTestMachineCode(root)
	rootBody.call(wrapper)
	rootBody.call(unrelated)
	rootBody.emit(0xc3)
	wrapperBody := newTestMachineCode(wrapper)
	wrapperBody.call(callback)
	wrapperBody.call(collector)
	wrapperBody.call(callback)
	wrapperBody.emit(0xc3)
	unrelatedBody := []byte{0xff, 0xd0, 0xc3} // call rax; ret
	starts := []uint64{
		wrapper,
		wrapper + uint64(len(wrapperBody.data)),
		unrelated,
		unrelated + uint64(len(unrelatedBody)),
		collector,
		0x1600,
	}
	file := newProbeTestELF(t, map[uint64][]byte{
		root: rootBody.data, wrapper: wrapperBody.data, unrelated: unrelatedBody,
	}, starts)

	target, err := collectorFromRepeatedCallShape(file, starts, root, uint64(len(rootBody.data)))
	require.NoError(t, err)
	assert.Equal(t, collector, target)
}

func TestDerivePrivateCollectorProbe(t *testing.T) {
	const root, callback, collector = uint64(0x1100), uint64(0x1400), uint64(0x1500)
	body := newTestMachineCode(root)
	body.call(callback)
	body.call(collector)
	body.call(callback)
	body.emit(0xc3)
	file := newProbeTestELF(t, map[uint64][]byte{root: body.data}, []uint64{collector, 0x1600})

	probe, err := derivePrivateCollectorProbe(file, pythonVersion{major: 3, minor: 12}, root, uint64(len(body.data)))
	require.NoError(t, err)
	assert.Equal(t, GCCompletionProbePrivateReturn, probe.Kind)
	assert.Equal(t, testCodeFileOffset+collector-testCodeBaseAddress, probe.FileOffset)

	_, err = derivePrivateCollectorProbe(file, pythonVersion{major: 3, minor: 12}, root, 0)
	require.ErrorIs(t, err, errUnsupportedLayout)
	_, err = derivePrivateCollectorProbe(
		file,
		pythonVersion{major: 3, minor: 12},
		root,
		maximumPythonFunctionSize+1,
	)
	require.ErrorIs(t, err, errUnsupportedLayout)
	_, err = derivePrivateCollectorProbe(file, pythonVersion{major: 3, minor: 13}, root, uint64(len(body.data)))
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestDerivePrivateCollectorProbeFromThreadStateCall(t *testing.T) {
	const root, collector = uint64(0x1100), uint64(0x1500)
	body := newTestMachineCode(root)
	body.threadStateLookup()
	body.collectorCall(collector)
	body.emit(0xc3)
	file := newProbeTestELF(t, map[uint64][]byte{root: body.data}, []uint64{collector, 0x1600})

	probe, err := derivePrivateCollectorProbe(
		file,
		pythonVersion{major: 3, minor: 13},
		root,
		uint64(len(body.data)),
	)
	require.NoError(t, err)
	assert.Equal(t, GCCompletionProbePrivateReturn, probe.Kind)
	assert.Equal(t, testCodeFileOffset+collector-testCodeBaseAddress, probe.FileOffset)
}

func TestMatchThreadStateLookup(t *testing.T) {
	file := newProbeTestELF(t, nil, nil)
	state := threadStateCallMatchState{reachable: true}
	branchStates := map[uint64]threadStateCallMatchState{}
	instructions := []decodedInstruction{
		{inst: x86asm.Inst{Op: x86asm.LEA, Args: x86asm.Args{
			x86asm.RDI, x86asm.Mem{Base: x86asm.RIP, Disp: 0x21473b},
		}}},
		{address: 0x1200, inst: x86asm.Inst{Op: x86asm.CALL, Len: 5, Args: x86asm.Args{
			x86asm.Rel(int64(testPLTAddress) - int64(0x1200+5)),
		}}},
		{inst: x86asm.Inst{Op: x86asm.MOV, Args: x86asm.Args{
			x86asm.RBX, x86asm.Mem{Base: x86asm.RAX, Disp: 8},
		}}},
	}

	for _, decoded := range instructions {
		_, found, err := matchThreadStateCallInstruction(
			file, decoded, 0x1300, &state, branchStates,
		)
		require.NoError(t, err)
		assert.False(t, found)
	}
	assert.Equal(t, x86asm.RBX, state.thread)
	assert.True(t, state.hasThread)
}

func TestMatchThreadStateCollectorArguments(t *testing.T) {
	file := newProbeTestELF(t, nil, nil)
	state := threadStateCallMatchState{thread: x86asm.RBX, hasThread: true, reachable: true}
	branchStates := map[uint64]threadStateCallMatchState{}
	instructions := []decodedInstruction{
		{inst: x86asm.Inst{Op: x86asm.MOV, Args: x86asm.Args{x86asm.RDI, x86asm.RBX}}},
		{inst: x86asm.Inst{Op: x86asm.MOV, Args: x86asm.Args{x86asm.ESI, x86asm.Imm(2)}}},
		{inst: x86asm.Inst{Op: x86asm.MOV, Args: x86asm.Args{x86asm.EDX, x86asm.Imm(2)}}},
	}

	for _, decoded := range instructions {
		_, found, err := matchThreadStateCallInstruction(
			file, decoded, 0x1300, &state, branchStates,
		)
		require.NoError(t, err)
		assert.False(t, found)
	}
	assert.True(t, state.rdiReady)
	assert.True(t, state.rsiReady)
	assert.True(t, state.rdxReady)

	_, _, err := matchThreadStateCallInstruction(
		file,
		decodedInstruction{inst: x86asm.Inst{
			Op: x86asm.MOV, Args: x86asm.Args{x86asm.ESI, x86asm.Imm(1)},
		}},
		0x1300,
		&state,
		branchStates,
	)
	require.NoError(t, err)
	assert.False(t, state.rsiReady)
}

func TestMatchThreadStateCollectorCall(t *testing.T) {
	file := newProbeTestELF(t, nil, nil)
	branchStates := map[uint64]threadStateCallMatchState{}
	directCall := decodedInstruction{
		address: 0x1200,
		inst: x86asm.Inst{Op: x86asm.CALL, Len: 5, Args: x86asm.Args{
			x86asm.Rel(int64(0x1500) - int64(0x1200+5)),
		}},
	}
	state := threadStateCallMatchState{
		thread: x86asm.RBX, hasThread: true,
		rdiReady: true, rsiReady: true, rdxReady: true,
		reachable: true,
	}

	target, found, err := matchThreadStateCallInstruction(
		file, directCall, 0x1600, &state, branchStates,
	)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, uint64(0x1500), target)
	assert.False(t, state.hasThread)
}

func TestCollectorFromThreadStateCallShapeAcrossEarlyReturn(t *testing.T) {
	const root, collector = uint64(0x1100), uint64(0x1500)
	body := newTestMachineCode(root)
	body.threadStateLookup()
	collectorPath := body.address + uint64(len(body.data)) + 6 + 2
	body.jne(collectorPath)
	body.emit(0x5b, 0xc3) // pop rbx; ret
	body.collectorCall(collector)
	body.emit(0xc3)
	starts := []uint64{collector, 0x1600}
	file := newProbeTestELF(t, map[uint64][]byte{root: body.data}, starts)

	target, err := collectorFromThreadStateCallShape(file, starts, root, uint64(len(body.data)))
	require.NoError(t, err)
	assert.Equal(t, collector, target)
}

func TestCollectorFromThreadStateCallShapeRejectsMultipleCandidates(t *testing.T) {
	const root = uint64(0x1100)
	body := newTestMachineCode(root)
	body.threadStateLookup()
	body.collectorCall(0x1500)
	body.threadStateLookup()
	body.collectorCall(0x1520)
	body.emit(0xc3)
	starts := []uint64{0x1500, 0x1520, 0x1600}
	file := newProbeTestELF(t, map[uint64][]byte{root: body.data}, starts)

	_, err := collectorFromThreadStateCallShape(file, starts, root, uint64(len(body.data)))
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestCollectorFromThreadStateCallShapeRequiresFunctionStart(t *testing.T) {
	const root = uint64(0x1100)
	body := newTestMachineCode(root)
	body.threadStateLookup()
	body.collectorCall(0x1500)
	body.emit(0xc3)
	starts := []uint64{0x1520, 0x1600}
	file := newProbeTestELF(t, map[uint64][]byte{root: body.data}, starts)

	_, err := collectorFromThreadStateCallShape(file, starts, root, uint64(len(body.data)))
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestMatchThreadStateRegisterOverwrite(t *testing.T) {
	file := newProbeTestELF(t, nil, nil)
	branchStates := map[uint64]threadStateCallMatchState{}

	for name, inst := range map[string]x86asm.Inst{
		"pop 64-bit register": {Op: x86asm.POP, Args: x86asm.Args{x86asm.RBX}},
		"write 32-bit alias":  {Op: x86asm.MOV, Args: x86asm.Args{x86asm.EBX, x86asm.EAX}},
	} {
		t.Run(name, func(t *testing.T) {
			state := threadStateCallMatchState{
				thread: x86asm.RBX, hasThread: true,
				rdiReady: true, rsiReady: true, rdxReady: true,
				reachable: true,
			}
			_, _, err := matchThreadStateCallInstruction(
				file, decodedInstruction{inst: inst}, 0x1600, &state, branchStates,
			)
			require.NoError(t, err)
			assert.False(t, state.hasThread)
			assert.False(t, state.rdiReady)
			assert.False(t, state.rsiReady)
			assert.False(t, state.rdxReady)
		})
	}

	state := threadStateCallMatchState{thread: x86asm.RBX, hasThread: true, reachable: true}
	_, _, err := matchThreadStateCallInstruction(
		file,
		decodedInstruction{inst: x86asm.Inst{
			Op: x86asm.CMP, Args: x86asm.Args{x86asm.RBX, x86asm.Imm(0)},
		}},
		0x1600,
		&state,
		branchStates,
	)
	require.NoError(t, err)
	assert.True(t, state.hasThread)
}

func TestMatchThreadStatePLTCall(t *testing.T) {
	file := newProbeTestELF(t, nil, nil)
	branchStates := map[uint64]threadStateCallMatchState{}
	pltCall := decodedInstruction{
		address: 0x1200,
		inst: x86asm.Inst{Op: x86asm.CALL, Len: 5, Args: x86asm.Args{
			x86asm.Rel(int64(testPLTAddress) - int64(0x1200+5)),
		}},
	}

	state := threadStateCallMatchState{
		thread: x86asm.RBX, hasThread: true,
		rdiReady: true, rsiReady: true, rdxReady: true,
		reachable: true,
	}
	_, found, err := matchThreadStateCallInstruction(
		file, pltCall, 0x1600, &state, branchStates,
	)
	require.NoError(t, err)
	assert.False(t, found)
	assert.True(t, state.hasThread)
	assert.False(t, state.rdiReady)
	assert.False(t, state.rsiReady)
	assert.False(t, state.rdxReady)

	state.thread = x86asm.R10
	state.hasThread = true
	_, _, err = matchThreadStateCallInstruction(file, pltCall, 0x1600, &state, branchStates)
	require.NoError(t, err)
	assert.False(t, state.hasThread)
}

func TestMatchThreadStateRejectsIndirectCall(t *testing.T) {
	file := newProbeTestELF(t, nil, nil)
	state := threadStateCallMatchState{
		thread: x86asm.RBX, hasThread: true,
		rdiReady: true, rsiReady: true, rdxReady: true,
		reachable: true,
	}

	_, _, err := matchThreadStateCallInstruction(
		file,
		decodedInstruction{inst: x86asm.Inst{
			Op: x86asm.CALL, Len: 2, Args: x86asm.Args{x86asm.RAX},
		}},
		0x1600,
		&state,
		map[uint64]threadStateCallMatchState{},
	)
	require.ErrorIs(t, err, errUnsupportedLayout)
}

type testMachineCode struct {
	address uint64
	data    []byte
}

func newTestMachineCode(address uint64) *testMachineCode {
	return &testMachineCode{address: address}
}

func (code *testMachineCode) emit(data ...byte) {
	code.data = append(code.data, data...)
}

func (code *testMachineCode) call(target uint64) {
	next := code.address + uint64(len(code.data)) + 5
	relative := int64(target) - int64(next)
	code.emit(0xe8, byte(relative), byte(relative>>8), byte(relative>>16), byte(relative>>24))
}

func (code *testMachineCode) threadStateLookup() {
	code.emit(0x48, 0x8d, 0x3d, 0, 0, 0, 0) // lea rdi,[rip+0]
	code.call(testPLTAddress)
	code.emit(0x48, 0x8b, 0x58, 0x08) // mov rbx,[rax+8]
}

func (code *testMachineCode) collectorCall(target uint64) {
	code.emit(0x48, 0x89, 0xdf) // mov rdi,rbx
	code.emit(0xba, 2, 0, 0, 0) // mov edx,2
	code.emit(0xbe, 2, 0, 0, 0) // mov esi,2
	code.call(target)
}

func (code *testMachineCode) jne(target uint64) {
	next := code.address + uint64(len(code.data)) + 6
	relative := int64(target) - int64(next)
	code.emit(0x0f, 0x85, byte(relative), byte(relative>>8), byte(relative>>16), byte(relative>>24))
}

func newProbeTestELF(t *testing.T, functions map[uint64][]byte, starts []uint64) *elf.File {
	t.Helper()
	code := make([]byte, testCodeSegmentSize)
	for address, body := range functions {
		offset := address - testCodeBaseAddress
		require.LessOrEqual(t, offset+uint64(len(body)), uint64(len(code)))
		copy(code[offset:], body)
	}
	header := functionStartTable(starts)
	return &elf.File{
		FileHeader: elf.FileHeader{
			Class: elf.ELFCLASS64, Data: elf.ELFDATA2LSB,
			ByteOrder: binary.LittleEndian, Machine: elf.EM_X86_64,
		},
		Progs: []*elf.Prog{{
			ProgHeader: elf.ProgHeader{
				Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: testCodeFileOffset,
				Vaddr: testCodeBaseAddress, Filesz: uint64(len(code)), Memsz: uint64(len(code)),
			},
			ReaderAt: bytes.NewReader(code),
		}},
		Sections: []*elf.Section{
			{
				SectionHeader: elf.SectionHeader{
					Name: ".eh_frame_hdr", Type: elf.SHT_PROGBITS,
					Addr: testFrameHeaderAddress, Size: uint64(len(header)),
				},
				ReaderAt: bytes.NewReader(header),
			},
			{
				SectionHeader: elf.SectionHeader{
					Name: ".plt", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR,
					Addr: testPLTAddress, Size: 0x40,
				},
			},
		},
	}
}

func functionStartTable(starts []uint64) []byte {
	data := make([]byte, ehFrameHeaderSize+len(starts)*ehFrameTableEntrySize)
	copy(data, supportedEHFrameHeaderEncoding[:])
	binary.LittleEndian.PutUint32(
		data[ehFrameHeaderSize-ehFrameEncodedFieldSize:ehFrameHeaderSize],
		uint32(len(starts)),
	)
	for index, start := range starts {
		offset := ehFrameHeaderSize + index*ehFrameTableEntrySize
		delta := int32(int64(start) - int64(testFrameHeaderAddress))
		binary.LittleEndian.PutUint32(data[offset:offset+ehFrameEncodedFieldSize], uint32(delta))
	}
	return data
}
