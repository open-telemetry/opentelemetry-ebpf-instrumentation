// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// Synthetic ELF layout used by all moduledata tests.
//
// Virtual address map:
//
//	[0x1000, 0x1800)  .text   — executable, flags RX
//	[0x3000, 0x3080)  .gopclntab — read-only, flags R
//	[0x4000, 0x4300)  .data   — writable, flags RW; runtime.moduledata lives at 0x4000
//
// File offset map (compact, no gaps between sections):
//
//	0x0000  ELF header     (64 B)
//	0x0040  3× PT_LOAD     (3 × 56 = 168 B)
//	0x0100  .text data     (0x800 B)
//	0x0900  .gopclntab     (0x80 B)
//	0x0980  .data          (0x300 B)  ← moduledata at file offset 0x0980
//	0x0C80  .shstrtab      (34 B)
//	0x0D00  section hdrs   (5 × 64 B)
//	0x0E40  end-of-file
const (
	testTextVMA      uint64 = 0x1000
	testTextSize     uint64 = 0x800
	testGopclntabVMA uint64 = 0x3000
	testGopclntabSz  uint64 = 0x80
	testDataVMA      uint64 = 0x4000
	testDataSize     uint64 = 0x300

	// Known field offsets for Go 1.17+ (verified through Go 1.26).
	testMDPcHeader  uint64 = 0
	testMDPclntable uint64 = 104
	testMDMinpc     uint64 = 160
	testMDMaxpc     uint64 = 168
	testMDText      uint64 = 176
	testMDEtext     uint64 = 184
)

var testMDOffsets = moduledataOffsets{
	pcHeader:  testMDPcHeader,
	pclntable: testMDPclntable,
	minpc:     testMDMinpc,
	maxpc:     testMDMaxpc,
	text:      testMDText,
	etext:     testMDEtext,
}

// ELF struct sizes (Elf64_* ABI, fixed for 64-bit).
const (
	elfHeaderSize = 64
	elfPhdrSize   = 56
	elfShdrSize   = 64
)

// Byte offsets of section names within the .shstrtab literal used by buildTestELF:
// "\x00.text\x00.gopclntab\x00.data\x00.shstrtab\x00"
const (
	shstrtabOffText      = 1
	shstrtabOffGopclntab = 7
	shstrtabOffData      = 18
	shstrtabOffShstrtab  = 24
)

// buildTestELF constructs a minimal but structurally valid 64-bit little-endian ELF
// (ET_EXEC, EM_X86_64) in memory and returns an *elf.File backed by it.
//
// pclntableData is the value written into the runtime.moduledata pclntable.data field.
// All other moduledata fields are fixed (pcHeader = testGopclntabVMA, text = testTextVMA, …).
func buildTestELF(t *testing.T, pclntableData uint64) *elf.File {
	t.Helper()

	const (
		textFileOff      = 0x0100
		gopclntabFileOff = 0x0900
		dataFileOff      = 0x0980
		shstrtabFileOff  = 0x0C80
		shdrsFileOff     = 0x0D00
		numSections      = 5 // NULL + .text + .gopclntab + .data + .shstrtab
		numSegments      = 3 // RX (.text), R (.gopclntab), RW (.data)
		fileSize         = shdrsFileOff + numSections*elfShdrSize
	)

	buf := make([]byte, fileSize)
	le := binary.LittleEndian

	put16 := func(off int, v uint16) { le.PutUint16(buf[off:], v) }
	put32 := func(off int, v uint32) { le.PutUint32(buf[off:], v) }
	put64 := func(off int, v uint64) { le.PutUint64(buf[off:], v) }

	// ── ELF header ──────────────────────────────────────────────────────────────
	copy(buf[0:], "\x7fELF")
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	put16(16, uint16(elf.ET_EXEC))    // e_type
	put16(18, uint16(elf.EM_X86_64))  // e_machine
	put32(20, uint32(elf.EV_CURRENT)) // e_version
	put64(24, testTextVMA)            // e_entry
	put64(32, elfHeaderSize)          // e_phoff
	put64(40, shdrsFileOff)           // e_shoff
	put32(48, 0)                      // e_flags
	put16(52, elfHeaderSize)          // e_ehsize
	put16(54, elfPhdrSize)            // e_phentsize
	put16(56, numSegments)            // e_phnum
	put16(58, elfShdrSize)            // e_shentsize
	put16(60, numSections)            // e_shnum
	put16(62, 4)                      // e_shstrndx = section 4 (.shstrtab)

	// ── Program headers ─────────────────────────────────────────────────────────

	// Segment 0: RX  →  .text
	ph := elfHeaderSize
	put32(ph+0, uint32(elf.PT_LOAD))       // p_type
	put32(ph+4, uint32(elf.PF_R|elf.PF_X)) // p_flags
	put64(ph+8, textFileOff)               // p_offset
	put64(ph+16, testTextVMA)              // p_vaddr
	put64(ph+24, testTextVMA)              // p_paddr
	put64(ph+32, testTextSize)             // p_filesz
	put64(ph+40, testTextSize)             // p_memsz
	put64(ph+48, 0x1000)                   // p_align

	// Segment 1: R   →  .gopclntab
	ph = elfHeaderSize + elfPhdrSize
	put32(ph+0, uint32(elf.PT_LOAD)) // p_type
	put32(ph+4, uint32(elf.PF_R))    // p_flags
	put64(ph+8, gopclntabFileOff)    // p_offset
	put64(ph+16, testGopclntabVMA)   // p_vaddr
	put64(ph+24, testGopclntabVMA)   // p_paddr
	put64(ph+32, testGopclntabSz)    // p_filesz
	put64(ph+40, testGopclntabSz)    // p_memsz
	put64(ph+48, 0x1000)             // p_align

	// Segment 2: RW  →  .data
	ph = elfHeaderSize + elfPhdrSize*2
	put32(ph+0, uint32(elf.PT_LOAD))       // p_type
	put32(ph+4, uint32(elf.PF_R|elf.PF_W)) // p_flags
	put64(ph+8, dataFileOff)               // p_offset
	put64(ph+16, testDataVMA)              // p_vaddr
	put64(ph+24, testDataVMA)              // p_paddr
	put64(ph+32, testDataSize)             // p_filesz
	put64(ph+40, testDataSize)             // p_memsz
	put64(ph+48, 0x1000)                   // p_align

	// ── moduledata fields in .data ───────────────────────────────────────────────
	db := dataFileOff
	put64(db+int(testMDPcHeader), testGopclntabVMA)      // pcHeader  → exact gopclntab start
	put64(db+int(testMDPclntable), pclntableData)        // pclntable.data (caller-supplied)
	put64(db+int(testMDMinpc), testTextVMA)              // minpc
	put64(db+int(testMDMaxpc), testTextVMA+testTextSize) // maxpc
	put64(db+int(testMDText), testTextVMA)               // text
	put64(db+int(testMDEtext), testTextVMA+testTextSize) // etext

	// ── .shstrtab ────────────────────────────────────────────────────────────────
	shstrtab := "\x00.text\x00.gopclntab\x00.data\x00.shstrtab\x00"
	copy(buf[shstrtabFileOff:], shstrtab)

	// ── Section headers ──────────────────────────────────────────────────────────
	sh := func(idx int) int { return shdrsFileOff + idx*elfShdrSize }

	// Section 0: NULL (all zeros, already set)

	// Section 1: .text
	put32(sh(1)+0, shstrtabOffText)
	put32(sh(1)+4, uint32(elf.SHT_PROGBITS))
	put64(sh(1)+8, uint64(elf.SHF_ALLOC|elf.SHF_EXECINSTR))
	put64(sh(1)+16, testTextVMA)
	put64(sh(1)+24, textFileOff)
	put64(sh(1)+32, testTextSize)

	// Section 2: .gopclntab
	put32(sh(2)+0, shstrtabOffGopclntab)
	put32(sh(2)+4, uint32(elf.SHT_PROGBITS))
	put64(sh(2)+8, uint64(elf.SHF_ALLOC))
	put64(sh(2)+16, testGopclntabVMA)
	put64(sh(2)+24, gopclntabFileOff)
	put64(sh(2)+32, testGopclntabSz)

	// Section 3: .data
	put32(sh(3)+0, shstrtabOffData)
	put32(sh(3)+4, uint32(elf.SHT_PROGBITS))
	put64(sh(3)+8, uint64(elf.SHF_ALLOC|elf.SHF_WRITE))
	put64(sh(3)+16, testDataVMA)
	put64(sh(3)+24, dataFileOff)
	put64(sh(3)+32, testDataSize)

	// Section 4: .shstrtab
	put32(sh(4)+0, shstrtabOffShstrtab)
	put32(sh(4)+4, uint32(elf.SHT_STRTAB))
	put64(sh(4)+8, 0)  // no flags
	put64(sh(4)+16, 0) // addr = 0 (not loaded)
	put64(sh(4)+24, shstrtabFileOff)
	put64(sh(4)+32, uint64(len(shstrtab)))

	f, err := elf.NewFile(bytes.NewReader(buf))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// emptyRelocs returns a zero-populated relocationInfo (no RELA, no RELR).
func emptyRelocs() relocationInfo {
	return relocationInfo{
		explicit: map[uint64]uint64{},
		relr:     map[uint64]struct{}{},
	}
}

// ── validateModuledata ────────────────────────────────────────────────────────

// TestValidateModuledata_PclntableDataAtGopclntabStart exercises the pure-Go
// static binary case where pclntable.data == gopclntabAddr (exact start).
func TestValidateModuledata_PclntableDataAtGopclntabStart(t *testing.T) {
	elfF := buildTestELF(t, testGopclntabVMA) // pclntable.data == gopclntab start
	text, ok := validateModuledata(elfF, testDataVMA, testGopclntabVMA, testGopclntabSz, testMDOffsets, emptyRelocs())
	require.True(t, ok)
	require.Equal(t, testTextVMA, text)
}

// TestValidateModuledata_PclntableDataWithinGopclntab is the CGo PIE regression
// test (docker-proxy).  pclntable.data points to an internal function-table slice
// inside .gopclntab rather than to its start.  The old code rejected this candidate
// because it checked for exact equality; the fixed code accepts it.
func TestValidateModuledata_PclntableDataWithinGopclntab(t *testing.T) {
	pclntableData := testGopclntabVMA + 0x10 // well inside [gopclntab, gopclntab+size)
	elfF := buildTestELF(t, pclntableData)
	text, ok := validateModuledata(elfF, testDataVMA, testGopclntabVMA, testGopclntabSz, testMDOffsets, emptyRelocs())
	require.True(t, ok)
	require.Equal(t, testTextVMA, text)
}

// TestValidateModuledata_PclntableDataOutOfRange checks that a candidate is
// rejected when pclntable.data falls outside .gopclntab entirely.
func TestValidateModuledata_PclntableDataOutOfRange(t *testing.T) {
	pclntableData := testGopclntabVMA - 1 // just before .gopclntab → invalid
	elfF := buildTestELF(t, pclntableData)
	_, ok := validateModuledata(elfF, testDataVMA, testGopclntabVMA, testGopclntabSz, testMDOffsets, emptyRelocs())
	require.False(t, ok)
}

// TestValidateModuledata_WrongPcHeader checks that a candidate is rejected when
// pcHeader does not point to the exact start of .gopclntab.  We inject a wrong
// value via relocs.explicit so the ELF file data stays valid; only the resolved
// pointer is changed.
func TestValidateModuledata_WrongPcHeader(t *testing.T) {
	elfF := buildTestELF(t, testGopclntabVMA)

	// Override pcHeader to point one word past the gopclntab start.
	relocs := relocationInfo{
		explicit: map[uint64]uint64{
			testDataVMA + testMDPcHeader: testGopclntabVMA + 8, // wrong: not the gopclntab start
		},
		relr: map[uint64]struct{}{},
	}

	_, ok := validateModuledata(elfF, testDataVMA, testGopclntabVMA, testGopclntabSz, testMDOffsets, relocs)
	require.False(t, ok)
}

// ── moduledataCandidates ─────────────────────────────────────────────────────

// TestModuledataCandidates_StrategySectionScan verifies strategy 4 (direct
// section scan): for a pure-Go static binary the .data section contains
// gopclntabVMA as an absolute pointer, and the scan derives testDataVMA as a
// candidate moduledata address.
func TestModuledataCandidates_StrategySectionScan(t *testing.T) {
	// pclntable.data == gopclntabVMA so the data section contains that value
	// twice (at pcHeader and pclntable offsets), giving the scanner two shots at
	// deriving testDataVMA.
	elfF := buildTestELF(t, testGopclntabVMA)
	candidates := moduledataCandidates(elfF, testGopclntabVMA, testMDOffsets, emptyRelocs())
	require.Contains(t, candidates, testDataVMA)
}

// TestModuledataCandidates_StrategyRELA verifies strategy 2 (RELA): an explicit
// relocation entry whose addend equals gopclntabVMA is used to derive the
// candidate moduledata address.
func TestModuledataCandidates_StrategyRELA(t *testing.T) {
	elfF := buildTestELF(t, testGopclntabVMA)

	relocs := relocationInfo{
		explicit: map[uint64]uint64{
			testDataVMA + testMDPclntable: testGopclntabVMA, // RELA: pclntable.data → gopclntabVMA
		},
		relr: map[uint64]struct{}{},
	}

	candidates := moduledataCandidates(elfF, testGopclntabVMA, testMDOffsets, relocs)
	require.Contains(t, candidates, testDataVMA)
}

// TestModuledataCandidates_StrategyRELR verifies strategy 3 (RELR): when the
// pclntable.data field address is present in the RELR set, the candidate
// testDataVMA is derived from it.
func TestModuledataCandidates_StrategyRELR(t *testing.T) {
	// pclntable.data is within gopclntab (not at start) — typical CGo PIE layout.
	// The only way the candidate is found is via the RELR entry at the field address.
	pclntableData := testGopclntabVMA + 0x10
	elfF := buildTestELF(t, pclntableData)

	relocs := relocationInfo{
		explicit: map[uint64]uint64{},
		relr: map[uint64]struct{}{
			testDataVMA + testMDPclntable: {}, // pclntable.data field is RELR-backed
		},
	}
	candidates := moduledataCandidates(elfF, testGopclntabVMA, testMDOffsets, relocs)
	require.Contains(t, candidates, testDataVMA)
}

// TestModuledataCandidates_Deduplication verifies that a candidate address
// produced by more than one strategy appears exactly once in the output.
// Both strategy 2 (RELA at the pcHeader field) and strategy 4 (section scan
// finding gopclntabVMA at the same address) call tryPointerField(testDataVMA),
// but the internal seen-map must suppress the duplicate.
func TestModuledataCandidates_Deduplication(t *testing.T) {
	elfF := buildTestELF(t, testGopclntabVMA)

	relocs := relocationInfo{
		explicit: map[uint64]uint64{
			testDataVMA + testMDPcHeader: testGopclntabVMA, // RELA at pcHeader field
		},
		relr: map[uint64]struct{}{},
	}

	candidates := moduledataCandidates(elfF, testGopclntabVMA, testMDOffsets, relocs)

	count := 0
	for _, c := range candidates {
		if c == testDataVMA {
			count++
		}
	}
	require.Equal(t, 1, count, "testDataVMA must appear exactly once despite being produced by two strategies")
}

// ── full pipeline (moduledataCandidates + validateModuledata) ────────────────

// TestModuledataPipeline_CgoPIE is an end-to-end regression test for the
// docker-proxy bug: CGo PIE binary where pclntable.data points into .gopclntab
// at an internal function-table offset (not its start).  The old code rejected
// every candidate; the fixed range check accepts the correct one.
func TestModuledataPipeline_CgoPIE(t *testing.T) {
	pclntableData := testGopclntabVMA + 0x10
	elfF := buildTestELF(t, pclntableData)

	relocs := relocationInfo{
		explicit: map[uint64]uint64{},
		relr: map[uint64]struct{}{
			testDataVMA + testMDPclntable: {},
		},
	}

	candidates := moduledataCandidates(elfF, testGopclntabVMA, testMDOffsets, relocs)
	require.Contains(t, candidates, testDataVMA, "candidate should be generated via RELR strategy")

	text, ok := validateModuledata(elfF, testDataVMA, testGopclntabVMA, testGopclntabSz, testMDOffsets, relocs)
	require.True(t, ok)
	require.Equal(t, testTextVMA, text)
}

// ── decodeRelr ───────────────────────────────────────────────────────────────

// TestDecodeRelr_AddressAndBitmap exercises both RELR word types:
//   - an explicit-address word (LSB = 0) that relocates a single slot and
//     advances the base pointer
//   - a bitmap word (LSB = 1) whose bits [0..62] select further slots relative
//     to the current base
func TestDecodeRelr_AddressAndBitmap(t *testing.T) {
	le := binary.LittleEndian
	buf := make([]byte, 24)

	// Word 0: address entry 0x1000 (LSB=0) → adds 0x1000, base advances to 0x1008.
	le.PutUint64(buf[0:], 0x1000)

	// Word 1: bitmap entry (LSB=1), bitmap = 0b101 = 5 (bits 0 and 2 set).
	//   bit 0 → base+0   = 0x1008
	//   bit 2 → base+16  = 0x1018
	//   encoded word = (bitmap << 1) | 1 = (5 << 1) | 1 = 0xb
	le.PutUint64(buf[8:], 0xb)

	// Word 2: address entry 0x2000 (LSB=0) → adds 0x2000.
	le.PutUint64(buf[16:], 0x2000)

	result := map[uint64]struct{}{}
	decodeRelr(result, buf, le)

	require.Contains(t, result, uint64(0x1000))
	require.Contains(t, result, uint64(0x1008))
	require.Contains(t, result, uint64(0x1018))
	require.Contains(t, result, uint64(0x2000))
	require.Len(t, result, 4)
}
