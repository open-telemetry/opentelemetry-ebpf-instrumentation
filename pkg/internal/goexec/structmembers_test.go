// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/grafana/go-offsets-tracker/pkg/offsets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/tools"
)

var (
	debugData           *dwarf.Data
	grpcElf             *dwarf.Data
	spanContextData     *dwarf.Data
	smallELF            *elf.File
	smallGRPCElf        *elf.File
	smallSpanContextELF *elf.File
)

func compileELF(source string, extraArgs ...string) *elf.File {
	tempDir := os.TempDir()
	tmpFilePath := path.Join(tempDir, "server.testexec")
	cmdParts := []string{"build"}
	cmdParts = append(cmdParts, extraArgs...)
	cmdParts = append(cmdParts, "-o", tmpFilePath, source)
	cmd := exec.Command("go", cmdParts...)
	cmd.Env = []string{"GOOS=linux", "HOME=" + tempDir, "TMPDIR=" + tempDir}
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		fmt.Println("command output:\n" + out.String())
		panic(err)
	}
	execELF, err := elf.Open(tmpFilePath)
	if err != nil {
		panic(err)
	}
	return execELF
}

func TestMain(m *testing.M) {
	var err error
	baseDir := tools.ProjectDir()
	// Compiling the same executable twice, with and without debug data so we can inspect it later in the tests
	debugData, err = compileELF(baseDir + "/internal/test/cmd/pingserver/server.go").DWARF()
	if err != nil {
		panic(err)
	}
	smallELF = compileELF(baseDir+"/internal/test/cmd/pingserver/server.go", "-ldflags", "-s -w")
	grpcElf, err = compileELF(baseDir + "/internal/test/cmd/grpc/server/server.go").DWARF()
	if err != nil {
		panic(err)
	}
	smallGRPCElf = compileELF(baseDir+"/internal/test/cmd/grpc/server/server.go", "-ldflags", "-s -w")
	spanContextData, err = compileELF(baseDir + "/configs/offsets/oteltrace/inspect.go").DWARF()
	if err != nil {
		panic(err)
	}
	smallSpanContextELF = compileELF(baseDir+"/configs/offsets/oteltrace/inspect.go", "-ldflags", "-s -w")
	m.Run()
}

func mustMatch(t *testing.T, expected, actual FieldOffsets) {
	for key, value := range expected {
		assert.Equal(t, value, actual[key], "key: %s", key)
	}
}

func TestGoOffsetsFromDwarf(t *testing.T) {
	offsets, _ := structMemberOffsetsFromDwarf(debugData)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		URLPtrPos:         uint64(16),
		PathPtrPos:        uint64(56),
		ConnFdPos:         uint64(0),
		FdLaddrPos:        uint64(96),
		MethodPtrPos:      uint64(0),
		TCPAddrIPPtrPos:   uint64(0),
		TCPAddrPortPtrPos: uint64(24),
		HchanQcountPos:    uint64(0),
		HchanDataqsizPos:  uint64(8),
		HchanSendxPos:     uint64(48),
		HchanRecvxPos:     uint64(56),
	}, offsets)
}

func TestGrpcOffsetsFromDwarf(t *testing.T) {
	offsets, _ := structMemberOffsetsFromDwarf(grpcElf)
	// this test might fail if a future Go gRPC version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		GrpcServerStreamStPtr:  uint64(0x148),
		GrpcStreamMethodPtrPos: uint64(0x10),
		GrpcStatusSPos:         uint64(0),
		ConnFdPos:              uint64(0),
		FdLaddrPos:             uint64(96),
		GrpcStatusCodePtrPos:   uint64(40),
	}, offsets)
}

func TestGoOffsetsWithoutDwarf(t *testing.T) {
	offsets, err := structMemberOffsets(smallELF)
	require.NoError(t, err)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		URLPtrPos:                         uint64(16),
		PathPtrPos:                        uint64(56),
		ConnFdPos:                         uint64(0),
		FdLaddrPos:                        uint64(96),
		MethodPtrPos:                      uint64(0),
		HchanQcountPos:                    uint64(0),
		HchanDataqsizPos:                  uint64(8),
		HchanSendxPos:                     uint64(48),
		HchanRecvxPos:                     uint64(56),
		RuntimeGCControllerMemoryLimitPos: uint64(8),
		RuntimeGCControllerGCPercentPos:   uint64(0),
	}, offsets)
}

func TestGrpcOffsetsWithoutDwarf(t *testing.T) {
	offsets, _ := structMemberOffsets(smallGRPCElf)
	// this test might fail if a future Go gRPC version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		GrpcServerStreamStPtr:  uint64(0x148),
		GrpcStreamMethodPtrPos: uint64(0x10),
		GrpcStatusSPos:         uint64(0),
		GrpcStatusCodePtrPos:   uint64(40),
		ConnFdPos:              uint64(0),
		FdLaddrPos:             uint64(96),
	}, offsets)
}

func TestSpanContextOffsetsFromDwarf(t *testing.T) {
	offsets, _ := structMemberOffsetsFromDwarf(spanContextData)
	mustMatch(t, FieldOffsets{
		SpanContextTraceIDPos:    uint64(0),
		SpanContextSpanIDPos:     uint64(16),
		SpanContextTraceFlagsPos: uint64(24),
	}, offsets)
}

func TestSpanContextOffsetsWithoutDwarf(t *testing.T) {
	offsets, err := structMemberOffsets(smallSpanContextELF)
	require.NoError(t, err)
	mustMatch(t, FieldOffsets{
		SpanContextTraceIDPos:    uint64(0),
		SpanContextSpanIDPos:     uint64(16),
		SpanContextTraceFlagsPos: uint64(24),
	}, offsets)
}

func TestGoOffsetsFromDwarf_ErrorIfConstantNotFound(t *testing.T) {
	structMembers["net/http.response"] = structInfo{
		lib: "go",
		fields: map[string]GoOffset{
			"tralara": 123456,
		},
	}
	_, missing := structMemberOffsetsFromDwarf(debugData)
	assert.Contains(t, missing, GoOffset(123456))
}

func TestReadMembers_UnsupportedLocationType(t *testing.T) {
	fdr := &fakeDwarfReader{
		entries: []*dwarf.Entry{
			{
				Tag: dwarf.TagStructType,
				Field: []dwarf.Field{
					{Attr: dwarf.AttrName, Val: "supported_loc"},
					{Attr: dwarf.AttrDataMemberLoc, Val: int64(33)},
				},
			}, {
				Tag: dwarf.TagStructType,
				Field: []dwarf.Field{
					{Attr: dwarf.AttrName, Val: "unsupported_loc"},
					{Attr: dwarf.AttrDataMemberLoc, Val: []byte("#\x00")},
				},
			},
		},
	}
	notFoundFields := map[GoOffset]struct{}{
		123456: {},
		234567: {},
	}
	// Must return an error if there is a field with unsupported location type
	require.Error(t, readMembers(fdr, map[string]GoOffset{
		"supported_loc":   123456,
		"unsupported_loc": 234567,
	}, notFoundFields, FieldOffsets{}))
	// And this field will be kept in the "expectedFields" map, so OBI will
	// later know that it didn't manage to get that information from dwarf
	// and will try to look for it in the precompiled offsets DB
	assert.Equal(t, map[GoOffset]struct{}{
		234567: {},
	}, notFoundFields)
}

func TestOffsetsForLibVersions(t *testing.T) {
	offsets := offsetsForLibVersions(FieldOffsets{}, map[string]string{
		"google.golang.org/grpc": "1.77.1",
		"golang.org/x/net":       "0.45.0",
		"github.com/lib/pq":      "1.11.2",
	}, slog.Default())

	mustMatch(t, FieldOffsets{
		GrpcOneSixZero:     uint64(1),
		GrpcOneSixNine:     uint64(1),
		GrpcOneSevenSeven:  uint64(1),
		HTTP2ZeroFortyFive: uint64(1),
		PqOneElevenZero:    uint64(1),
	}, offsets)
}

func TestOffsetsForLibVersions_PreVersionFlags(t *testing.T) {
	offsets := offsetsForLibVersions(FieldOffsets{}, map[string]string{
		"google.golang.org/grpc": "1.59.9",
		"golang.org/x/net":       "0.44.0",
		"github.com/lib/pq":      "1.10.9",
	}, slog.Default())

	mustMatch(t, FieldOffsets{
		GrpcOneSixZero:     uint64(0),
		GrpcOneSixNine:     uint64(0),
		GrpcOneSevenSeven:  uint64(0),
		HTTP2ZeroFortyFive: uint64(0),
		PqOneElevenZero:    uint64(0),
	}, offsets)
}

func TestPrefetchedGoRuntimeMemoryOffsets(t *testing.T) {
	track, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	tests := []struct {
		structName string
		fieldName  string
		go123      uint64
		go125      uint64
	}{
		{structName: "runtime.consistentHeapStats", fieldName: "stats", go123: 0, go125: 0},
		{structName: "runtime.heapStatsDelta", fieldName: "committed", go123: 0, go125: 0},
		{structName: "runtime.heapStatsDelta", fieldName: "inStacks", go123: 24, go125: 24},
		{structName: "runtime.heapStatsDelta", fieldName: "largeAlloc", go123: 56, go125: 48},
		{structName: "runtime.heapStatsDelta", fieldName: "largeAllocCount", go123: 64, go125: 56},
		{structName: "runtime.heapStatsDelta", fieldName: "smallAllocCount", go123: 72, go125: 64},
		{structName: "runtime.heapStatsDelta", fieldName: "smallFreeCount", go123: 632, go125: 624},
		{structName: "runtime.mstats", fieldName: "heapStats", go123: 0, go125: 0},
		{structName: "runtime.mstats", fieldName: "stacks_sys", go123: 3544, go125: 3520},
		{structName: "runtime.mstats", fieldName: "mspan_sys", go123: 3552, go125: 3528},
		{structName: "runtime.mstats", fieldName: "mcache_sys", go123: 3560, go125: 3536},
		{structName: "runtime.mstats", fieldName: "buckhash_sys", go123: 3568, go125: 3544},
		{structName: "runtime.mstats", fieldName: "gcMiscSys", go123: 3576, go125: 3552},
		{structName: "runtime.mstats", fieldName: "other_sys", go123: 3584, go125: 3560},
	}

	for _, tt := range tests {
		_, found := track.Find(tt.structName, tt.fieldName, "1.22.12")
		assert.False(t, found, "%s.%s should be unavailable before Go 1.23", tt.structName, tt.fieldName)

		offset, found := track.Find(tt.structName, tt.fieldName, "1.23.0")
		require.True(t, found, "%s.%s missing for Go 1.23", tt.structName, tt.fieldName)
		assert.Equal(t, tt.go123, offset, "%s.%s Go 1.23 offset", tt.structName, tt.fieldName)

		offset, found = track.Find(tt.structName, tt.fieldName, "1.25.0")
		require.True(t, found, "%s.%s missing for Go 1.25", tt.structName, tt.fieldName)
		assert.Equal(t, tt.go125, offset, "%s.%s Go 1.25 offset", tt.structName, tt.fieldName)
	}
}

type fakeDwarfReader struct {
	entries []*dwarf.Entry
}

func (f *fakeDwarfReader) Next() (*dwarf.Entry, error) {
	if len(f.entries) == 0 {
		return nil, nil
	}
	entry := f.entries[0]
	f.entries = f.entries[1:]
	return entry, nil
}
