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
	debugData    *dwarf.Data
	grpcElf      *dwarf.Data
	smallELF     *elf.File
	smallGRPCElf *elf.File
)

func compileELF(source string, extraArgs ...string) *elf.File {
	tempDir := os.TempDir()
	tmpFilePath := path.Join(tempDir, "server.testexec")
	cmdParts := []string{"build"}
	cmdParts = append(cmdParts, extraArgs...)
	cmdParts = append(cmdParts, "-o", tmpFilePath, source)
	cmd := exec.Command("go", cmdParts...)
	cmd.Env = []string{"GOOS=linux", "HOME=" + tempDir}
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
	m.Run()
}

func mustMatch(t *testing.T, expected, actual FieldOffsets) {
	for key, value := range expected {
		assert.Equal(t, value, actual[key], "key: %s", key)
	}
}

func nestedRuntimeOffsetTrack(gFree, mutexKey, gListSize uint64) *offsets.Track {
	const goVersion = "1.25.0"
	field := func(offset uint64) offsets.Field {
		return offsets.Field{
			Offsets: []offsets.Versioned{{Offset: offset, Since: goVersion}},
		}
	}

	return &offsets.Track{Data: map[string]offsets.Struct{
		"runtime.schedt": {"gFree": field(gFree)},
		"runtime.mutex":  {"key": field(mutexKey)},
		"runtime.gList":  {"size": field(gListSize)},
	}}
}

func dwarfStruct(t *testing.T, data *dwarf.Data, name string) (*dwarf.Reader, *dwarf.StructType) {
	t.Helper()

	reader := data.Reader()
	for {
		entry, err := reader.Next()
		require.NoError(t, err)
		if entry == nil {
			t.Fatalf("DWARF struct %q not found", name)
		}
		if entry.Tag != dwarf.TagStructType || entry.Val(dwarf.AttrName) != name {
			continue
		}

		typ, err := data.Type(entry.Offset)
		require.NoError(t, err)
		structType, ok := typ.(*dwarf.StructType)
		if ok && len(structType.Field) > 0 {
			return reader, structType
		}
	}
}

func dwarfStructField(t *testing.T, structType *dwarf.StructType, name string) *dwarf.StructField {
	t.Helper()

	for _, field := range structType.Field {
		if field.Name == name {
			return field
		}
	}
	t.Fatalf("DWARF field %q not found in %q", name, structType.StructName)
	return nil
}

func dwarfStructFieldTypeOffset(t *testing.T, data *dwarf.Data, structName, fieldName string) dwarf.Offset {
	t.Helper()

	reader, _ := dwarfStruct(t, data, structName)
	for {
		entry, err := reader.Next()
		require.NoError(t, err)
		if entry == nil || entry.Tag == 0 {
			t.Fatalf("DWARF field %q not found in %q", fieldName, structName)
		}
		if entry.Val(dwarf.AttrName) != fieldName {
			continue
		}

		typeOffset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
		require.True(t, ok)
		return typeOffset
	}
}

func nestedRuntimeOffsetsFromDwarf(t *testing.T, data *dwarf.Data) FieldOffsets {
	t.Helper()

	_, schedType := dwarfStruct(t, data, "runtime.schedt")
	gFreeField := dwarfStructField(t, schedType, "gFree")
	gFreeType, ok := gFreeField.Type.(*dwarf.StructType)
	require.True(t, ok)

	return FieldOffsets{
		RuntimeSchedGFreeStackPos: uint64(gFreeField.ByteOffset + dwarfStructField(t, gFreeType, "stack").ByteOffset),
		RuntimeSchedGFreeNoStackPos: uint64(
			gFreeField.ByteOffset + dwarfStructField(t, gFreeType, "noStack").ByteOffset,
		),
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

func TestNestedRuntimeOffsetsFromDwarf(t *testing.T) {
	offsets, missing := structMemberOffsetsFromDwarf(debugData)
	expected := nestedRuntimeOffsetsFromDwarf(t, debugData)

	require.NotContains(t, missing, RuntimeSchedGFreeStackPos)
	require.NotContains(t, missing, RuntimeSchedGFreeNoStackPos)
	assert.Equal(t, expected[RuntimeSchedGFreeStackPos], offsets[RuntimeSchedGFreeStackPos])
	assert.Equal(t, expected[RuntimeSchedGFreeNoStackPos], offsets[RuntimeSchedGFreeNoStackPos])
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

func TestNestedRuntimeOffsetsWithoutDwarf(t *testing.T) {
	offsets, err := structMemberOffsets(smallELF)
	require.NoError(t, err)
	expected := nestedRuntimeOffsetsFromDwarf(t, debugData)

	assert.Equal(t, expected[RuntimeSchedGFreeStackPos], offsets[RuntimeSchedGFreeStackPos])
	assert.Equal(t, expected[RuntimeSchedGFreeNoStackPos], offsets[RuntimeSchedGFreeNoStackPos])
}

func TestResolveNestedStructPreFetchedOffsets(t *testing.T) {
	const goVersion = "1.25.0"

	t.Run("resolves exact offsets", func(t *testing.T) {
		fieldOffsets := FieldOffsets{}
		resolveNestedStructPreFetchedOffsets(
			nestedRuntimeOffsetTrack(100, 4, 4), fieldOffsets, goVersion, slog.Default(),
		)

		assert.Equal(t, FieldOffsets{
			RuntimeSchedGFreeStackPos:   uint64(116),
			RuntimeSchedGFreeNoStackPos: uint64(124),
		}, fieldOffsets)
	})

	t.Run("preserves existing offsets", func(t *testing.T) {
		fieldOffsets := FieldOffsets{RuntimeSchedGFreeStackPos: uint64(999)}
		resolveNestedStructPreFetchedOffsets(
			nestedRuntimeOffsetTrack(100, 4, 4), fieldOffsets, goVersion, slog.Default(),
		)

		assert.Equal(t, uint64(999), fieldOffsets[RuntimeSchedGFreeStackPos])
		assert.Equal(t, uint64(124), fieldOffsets[RuntimeSchedGFreeNoStackPos])
	})

	t.Run("returns when both offsets exist", func(t *testing.T) {
		fieldOffsets := FieldOffsets{
			RuntimeSchedGFreeStackPos:   uint64(100),
			RuntimeSchedGFreeNoStackPos: uint64(200),
		}
		resolveNestedStructPreFetchedOffsets(&offsets.Track{}, fieldOffsets, goVersion, slog.Default())

		assert.Equal(t, FieldOffsets{
			RuntimeSchedGFreeStackPos:   uint64(100),
			RuntimeSchedGFreeNoStackPos: uint64(200),
		}, fieldOffsets)
	})

	missingDependencies := []struct {
		name   string
		remove func(*offsets.Track)
	}{
		{
			name: "gFree",
			remove: func(track *offsets.Track) {
				delete(track.Data, "runtime.schedt")
			},
		},
		{
			name: "mutex key",
			remove: func(track *offsets.Track) {
				delete(track.Data, "runtime.mutex")
			},
		},
		{
			name: "gList size",
			remove: func(track *offsets.Track) {
				delete(track.Data, "runtime.gList")
			},
		},
	}
	for _, tt := range missingDependencies {
		t.Run("missing "+tt.name, func(t *testing.T) {
			track := nestedRuntimeOffsetTrack(100, 4, 4)
			tt.remove(track)
			fieldOffsets := FieldOffsets{}

			resolveNestedStructPreFetchedOffsets(track, fieldOffsets, goVersion, slog.Default())

			assert.Empty(t, fieldOffsets)
		})
	}
}

func TestAlignRuntimeOffset(t *testing.T) {
	tests := []struct {
		name      string
		offset    uint64
		alignment uint64
		expected  uint64
	}{
		{name: "zero alignment", offset: 13, alignment: 0, expected: 13},
		{name: "already aligned", offset: 16, alignment: 8, expected: 16},
		{name: "rounds up", offset: 17, alignment: 8, expected: 24},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, alignRuntimeOffset(tt.offset, tt.alignment))
		})
	}
}

func TestResolveNestedStructOffsets(t *testing.T) {
	expectedOffsets := nestedRuntimeOffsetsFromDwarf(t, debugData)

	t.Run("resolves exact offsets", func(t *testing.T) {
		expectedReturns := map[GoOffset]struct{}{
			RuntimeSchedGFreeStackPos:   {},
			RuntimeSchedGFreeNoStackPos: {},
		}
		fieldOffsets := FieldOffsets{}

		resolveNestedStructOffsets(debugData, expectedReturns, fieldOffsets)

		assert.Equal(t, expectedOffsets, fieldOffsets)
		assert.Empty(t, expectedReturns)
	})

	t.Run("resolves requested offsets only", func(t *testing.T) {
		expectedReturns := map[GoOffset]struct{}{RuntimeSchedGFreeStackPos: {}}
		fieldOffsets := FieldOffsets{}

		resolveNestedStructOffsets(debugData, expectedReturns, fieldOffsets)

		assert.Equal(t, expectedOffsets[RuntimeSchedGFreeStackPos], fieldOffsets[RuntimeSchedGFreeStackPos])
		assert.NotContains(t, fieldOffsets, RuntimeSchedGFreeNoStackPos)
		assert.Empty(t, expectedReturns)
	})

	t.Run("returns when no nested offsets are requested", func(t *testing.T) {
		fieldOffsets := FieldOffsets{URLPtrPos: uint64(16)}

		resolveNestedStructOffsets(debugData, map[GoOffset]struct{}{}, fieldOffsets)

		assert.Equal(t, FieldOffsets{URLPtrPos: uint64(16)}, fieldOffsets)
	})
}

func TestResolveNestedStructOffsetsForType(t *testing.T) {
	reader, _ := dwarfStruct(t, debugData, "runtime.schedt")
	expectedReturns := map[GoOffset]struct{}{
		RuntimeSchedGFreeStackPos:   {},
		RuntimeSchedGFreeNoStackPos: {},
	}
	fieldOffsets := FieldOffsets{}

	resolveNestedStructOffsetsForType(
		debugData, reader, nestedRuntimeFields, expectedReturns, fieldOffsets,
	)

	assert.Equal(t, nestedRuntimeOffsetsFromDwarf(t, debugData), fieldOffsets)
	assert.Empty(t, expectedReturns)
}

func TestResolveNestedStructOffsetsForTypeSkipsIncompleteFields(t *testing.T) {
	childType := dwarfStructFieldTypeOffset(t, debugData, "runtime.schedt", "gFree")
	fields := []nestedStructField{
		{parentField: "missingLocation", childField: "stack", offset: GoOffset(1001)},
		{parentField: "invalidLocation", childField: "stack", offset: GoOffset(1002)},
		{parentField: "missingType", childField: "stack", offset: GoOffset(1003)},
		{parentField: "invalidType", childField: "stack", offset: GoOffset(1004)},
		{parentField: "missingChild", childField: "doesNotExist", offset: GoOffset(1005)},
	}
	reader := &fakeDwarfReader{entries: []*dwarf.Entry{
		{Field: []dwarf.Field{
			{Attr: dwarf.AttrName, Val: "missingLocation"},
			{Attr: dwarf.AttrType, Val: childType},
		}},
		{Field: []dwarf.Field{
			{Attr: dwarf.AttrName, Val: "invalidLocation"},
			{Attr: dwarf.AttrDataMemberLoc, Val: []byte{0}},
			{Attr: dwarf.AttrType, Val: childType},
		}},
		{Field: []dwarf.Field{
			{Attr: dwarf.AttrName, Val: "missingType"},
			{Attr: dwarf.AttrDataMemberLoc, Val: int64(10)},
		}},
		{Field: []dwarf.Field{
			{Attr: dwarf.AttrName, Val: "invalidType"},
			{Attr: dwarf.AttrDataMemberLoc, Val: int64(10)},
			{Attr: dwarf.AttrType, Val: "runtime.gFree"},
		}},
		{Field: []dwarf.Field{
			{Attr: dwarf.AttrName, Val: "missingChild"},
			{Attr: dwarf.AttrDataMemberLoc, Val: int64(10)},
			{Attr: dwarf.AttrType, Val: childType},
		}},
	}}
	expectedReturns := map[GoOffset]struct{}{}
	for _, field := range fields {
		expectedReturns[field.offset] = struct{}{}
	}

	fieldOffsets := FieldOffsets{}
	resolveNestedStructOffsetsForType(debugData, reader, fields, expectedReturns, fieldOffsets)

	assert.Empty(t, fieldOffsets)
	assert.Len(t, expectedReturns, len(fields))
}

func TestStructFieldOffset(t *testing.T) {
	childTypeOffset := dwarfStructFieldTypeOffset(t, debugData, "runtime.schedt", "gFree")
	_, schedType := dwarfStruct(t, debugData, "runtime.schedt")
	gFreeType, ok := dwarfStructField(t, schedType, "gFree").Type.(*dwarf.StructType)
	require.True(t, ok)

	for _, fieldName := range []string{"stack", "noStack"} {
		t.Run(fieldName, func(t *testing.T) {
			expected := dwarfStructField(t, gFreeType, fieldName).ByteOffset

			offset, found := structFieldOffset(debugData, childTypeOffset, fieldName)

			require.True(t, found)
			assert.Equal(t, uint64(expected), offset)
		})
	}

	t.Run("missing field", func(t *testing.T) {
		_, found := structFieldOffset(debugData, childTypeOffset, "doesNotExist")
		assert.False(t, found)
	})

	t.Run("invalid struct type", func(t *testing.T) {
		_, found := structFieldOffset(debugData, 0, "stack")
		assert.False(t, found)
	})
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
