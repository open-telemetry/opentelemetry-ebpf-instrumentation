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
	autoSDKSpanData     *dwarf.Data
	smallELF            *elf.File
	smallGRPCElf        *elf.File
	smallSpanContextELF *elf.File
	autoSDKSpanELF      *elf.File
	smallAutoSDKSpanELF *elf.File
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
	autoSDKSpanELF = compileELF(baseDir + "/configs/offsets/autosdk/inspect.go")
	autoSDKSpanData, err = autoSDKSpanELF.DWARF()
	if err != nil {
		panic(err)
	}
	smallAutoSDKSpanELF = compileELF(baseDir+"/configs/offsets/autosdk/inspect.go", "-ldflags", "-s -w")
	m.Run()
}

func mustMatch(t *testing.T, expected, actual FieldOffsets) {
	for key, value := range expected {
		assert.Equal(t, value, actual[key], "key: %s", key)
	}
}

func dwarfStruct(t *testing.T, data *dwarf.Data, name string) *dwarf.StructType {
	t.Helper()

	reader := data.Reader()
	for {
		entry, err := reader.Next()
		require.NoError(t, err)
		if entry == nil {
			t.Fatalf("DWARF struct %s not found", name)
		}
		if entry.Tag != dwarf.TagStructType || entry.Val(dwarf.AttrName) != name {
			continue
		}
		typeData, err := data.Type(entry.Offset)
		require.NoError(t, err)
		if structType, ok := typeData.(*dwarf.StructType); ok && len(structType.Field) > 0 {
			return structType
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
	t.Fatalf("DWARF field %s.%s not found", structType.StructName, name)
	return nil
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
	schedType := dwarfStruct(t, debugData, "runtime.schedt")
	gFreeField := dwarfStructField(t, schedType, "gFree")
	gFreeType, ok := gFreeField.Type.(*dwarf.StructType)
	require.True(t, ok)

	stack := uint64(gFreeField.ByteOffset + dwarfStructField(t, gFreeType, "stack").ByteOffset)
	noStack := uint64(gFreeField.ByteOffset + dwarfStructField(t, gFreeType, "noStack").ByteOffset)
	require.NotContains(t, missing, RuntimeSchedGFreeStackPos)
	require.NotContains(t, missing, RuntimeSchedGFreeNoStackPos)
	assert.Equal(t, stack, offsets[RuntimeSchedGFreeStackPos])
	assert.Equal(t, noStack, offsets[RuntimeSchedGFreeNoStackPos])
}

func TestGrpcOffsetsFromDwarf(t *testing.T) {
	offsets, _ := structMemberOffsetsFromDwarf(grpcElf)
	// this test might fail if a future Go gRPC version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		GrpcServerStreamStPtr:  uint64(0x168),
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

func TestHTTP2ClientConnTLSStateOffsets(t *testing.T) {
	offs, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	testCases := []struct {
		name       string
		structName string
		version    string
		want       uint64
	}{
		{
			name:       "x/net before tconnClosed removal",
			structName: "golang.org/x/net/http2.ClientConn",
			version:    "0.12.0",
			want:       32,
		},
		{
			name:       "x/net after tconnClosed removal",
			structName: "golang.org/x/net/http2.ClientConn",
			version:    "0.15.0",
			want:       24,
		},
		{
			name:       "vendored standard library",
			structName: "net/http.http2ClientConn",
			version:    "1.26.4",
			want:       24,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := offs.Find(tc.structName, "tlsState", tc.version)
			require.True(t, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGoRuntimeGCGoalFieldUnavailableAfterTrackedRange(t *testing.T) {
	offsets, err := structMemberOffsets(smallELF)
	require.NoError(t, err)

	assert.NotContains(t, offsets, RuntimeGCControllerHeapGoalPos)
}

func TestPrefetchedOffsetsPreserveResolvedOffsets(t *testing.T) {
	const resolvedOffset = uint64(999)
	resolved := FieldOffsets{
		RuntimeGCControllerGCPercentPos: resolvedOffset,
	}

	got, err := structMemberPreFetchedOffsets(smallELF, resolved)
	require.NoError(t, err)
	assert.Equal(t, resolvedOffset, got[RuntimeGCControllerGCPercentPos])
}

func TestGoroutineRuntimeOffsetsWithoutDwarf(t *testing.T) {
	offsets, err := structMemberOffsets(smallELF)
	require.NoError(t, err)
	schedType := dwarfStruct(t, debugData, "runtime.schedt")
	gFreeField := dwarfStructField(t, schedType, "gFree")
	gFreeType, ok := gFreeField.Type.(*dwarf.StructType)
	require.True(t, ok)

	assert.Equal(t,
		uint64(gFreeField.ByteOffset+dwarfStructField(t, gFreeType, "stack").ByteOffset),
		offsets[RuntimeSchedGFreeStackPos])
	assert.Equal(t,
		uint64(gFreeField.ByteOffset+dwarfStructField(t, gFreeType, "noStack").ByteOffset),
		offsets[RuntimeSchedGFreeNoStackPos])
	for _, field := range []GoOffset{
		RuntimeSchedNgSysPos,
		RuntimePFreeGPos,
		RuntimeGListSizePos,
	} {
		assert.IsType(t, uint64(0), offsets[field], "offset %d", field)
	}
}

func TestGrpcOffsetsWithoutDwarf(t *testing.T) {
	offsets, _ := structMemberOffsets(smallGRPCElf)
	// this test might fail if a future Go gRPC version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		GrpcServerStreamStPtr:  uint64(0x168),
		GrpcStreamStPtrPos:     uint64(0x168),
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

func TestCurrentAutoSDKDependencyABI(t *testing.T) {
	// This intentionally fails when the current Auto SDK layout or reviewed
	// module tuple changes.
	t.Run("with DWARF", func(t *testing.T) {
		offsets, _ := structMemberOffsetsFromDwarf(autoSDKSpanData)
		mustMatch(t, FieldOffsets{
			AutoSDKSpanContextPos: uint64(80),
		}, offsets)
	})

	t.Run("DWARF activation path", func(t *testing.T) {
		originalStructMembers := structMembers
		structMembers = map[string]structInfo{
			"go.opentelemetry.io/auto/sdk.span": {
				lib: "go.opentelemetry.io/auto/sdk",
				fields: map[string]GoOffset{
					"spanContext": AutoSDKSpanContextPos,
				},
			},
		}
		t.Cleanup(func() {
			structMembers = originalStructMembers
		})

		offsets, err := structMemberOffsets(autoSDKSpanELF)
		require.NoError(t, err)
		mustMatch(t, FieldOffsets{
			AutoSDKSpanContextPos:      uint64(80),
			AutoSDKActivationSupported: uint64(1),
		}, offsets)
	})

	t.Run("without DWARF", func(t *testing.T) {
		offsets, err := structMemberOffsets(smallAutoSDKSpanELF)
		require.NoError(t, err)
		mustMatch(t, FieldOffsets{
			AutoSDKSpanContextPos:      uint64(80),
			AutoSDKActivationSupported: uint64(1),
		}, offsets)
	})
}

func TestPrefetchedGoAutoSDKSpanContextOffsets(t *testing.T) {
	track, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	for _, sdkVersion := range []string{"1.1.0", "1.2.1"} {
		offset, found := track.Find(
			"go.opentelemetry.io/auto/sdk.span",
			"spanContext",
			sdkVersion,
		)
		require.True(t, found, "missing Auto SDK %s spanContext offset", sdkVersion)
		assert.Equal(t, uint64(80), offset)
	}
}

func TestPrefetchedGrpcStreamOffsets(t *testing.T) {
	track, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	for _, structName := range []string{
		"google.golang.org/grpc/internal/transport.ServerStream",
		"google.golang.org/grpc/internal/transport.Stream",
	} {
		assertPrefetchedOffset(t, track, structName, "st", "1.83.0", 0x148)
		assertPrefetchedOffset(t, track, structName, "st", "1.83.1", 0x168)
	}
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

func goAutoSDKActivationTestModules() moduleVersions {
	return moduleVersions{
		versions: map[string]string{
			"go.opentelemetry.io/auto/sdk":   "v1.2.1",
			"go.opentelemetry.io/otel":       "v1.45.0",
			"go.opentelemetry.io/otel/trace": "v1.45.0",
		},
		sums: map[string]string{
			"go.opentelemetry.io/auto/sdk":   "h1:jXsnJ4Lmnqd11kwkBV2LgLoFMZKizbCi5fNZ/ipaZ64=",
			"go.opentelemetry.io/otel":       "h1:pdrWmLHofpubmArBv1LgFSv1Z0Ie/ppdZzu+kUN5EeU=",
			"go.opentelemetry.io/otel/trace": "h1:l/mP6Uv7oNO7/TblbhpbgMidxhq1uO/rPsikOyVhxag=",
		},
		replacements: map[string]struct{}{},
	}
}

func TestGoAutoSDKActivationSupportsReviewedModules(t *testing.T) {
	t.Run("supported versions", func(t *testing.T) {
		assert.True(t, goAutoSDKActivationSupported(goAutoSDKActivationTestModules()))
	})

	t.Run("minimum versions", func(t *testing.T) {
		modules := goAutoSDKActivationTestModules()
		modules.versions["go.opentelemetry.io/auto/sdk"] = "v1.1.0"
		modules.sums["go.opentelemetry.io/auto/sdk"] = "h1:cH53jehLUN6UFLY71z+NDOiNJqDdPRaXzTel0sJySYA="
		modules.versions["go.opentelemetry.io/otel"] = "v1.33.0"
		modules.sums["go.opentelemetry.io/otel"] = "h1:/FerN9bax5LoK51X/sI0SVYrjSE0/yUL7DpxW4K3FWw="
		modules.versions["go.opentelemetry.io/otel/trace"] = "v1.33.0"
		modules.sums["go.opentelemetry.io/otel/trace"] = "h1:cCJuF7LRjUFso9LPnEAHJDB2pqzp+hbO8eu1qqW2d/s="
		assert.True(t, goAutoSDKActivationSupported(modules))
	})

	t.Run("unrelated replacement", func(t *testing.T) {
		modules := goAutoSDKActivationTestModules()
		modules.replacements["example.com/unrelated"] = struct{}{}
		assert.True(t, goAutoSDKActivationSupported(modules))
	})
}

func TestGoAutoSDKActivationRejectsInvalidModules(t *testing.T) {
	for _, module := range goAutoSDKActivationModules {
		t.Run("missing_"+module.path, func(t *testing.T) {
			modules := goAutoSDKActivationTestModules()
			delete(modules.versions, module.path)
			assert.False(t, goAutoSDKActivationSupported(modules))
		})

		t.Run("replaced_"+module.path, func(t *testing.T) {
			modules := goAutoSDKActivationTestModules()
			modules.replacements[module.path] = struct{}{}
			assert.False(t, goAutoSDKActivationSupported(modules))
		})

		t.Run("unsigned_"+module.path, func(t *testing.T) {
			modules := goAutoSDKActivationTestModules()
			delete(modules.sums, module.path)
			assert.False(t, goAutoSDKActivationSupported(modules))
		})
	}

	t.Run("empty checksum", func(t *testing.T) {
		modules := goAutoSDKActivationTestModules()
		modules.sums["go.opentelemetry.io/auto/sdk"] = ""
		assert.False(t, goAutoSDKActivationSupported(modules))
	})

	t.Run("noncanonical checksum", func(t *testing.T) {
		modules := goAutoSDKActivationTestModules()
		modules.sums["go.opentelemetry.io/auto/sdk"] = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		assert.False(t, goAutoSDKActivationSupported(modules))
	})

	t.Run("invalid build information", func(t *testing.T) {
		modules := goAutoSDKActivationTestModules()
		modules.invalid = true
		assert.False(t, goAutoSDKActivationSupported(modules))
	})
}

func TestGoAutoSDKActivationRejectsUnsupportedVersions(t *testing.T) {
	unsupportedVersions := []struct {
		module  string
		version string
	}{
		{module: "go.opentelemetry.io/auto/sdk", version: "v1.0.9"},
		{module: "go.opentelemetry.io/otel", version: "v1.32.9"},
		{module: "go.opentelemetry.io/otel/trace", version: "v1.32.9"},
		{module: "go.opentelemetry.io/auto/sdk", version: "v1.2.1-rc.1"},
		{module: "go.opentelemetry.io/otel", version: "v1.44.0+incompatible"},
	}
	for _, tt := range unsupportedVersions {
		t.Run(tt.module+"_"+tt.version, func(t *testing.T) {
			modules := goAutoSDKActivationTestModules()
			modules.versions[tt.module] = tt.version
			// Match the zero checksum returned by a failed allowlist lookup.
			modules.sums[tt.module] = ""
			assert.False(t, goAutoSDKActivationSupported(modules))
		})
	}
}

func TestSetGoAutoSDKActivationSupportClearsInvalidState(t *testing.T) {
	offsets := FieldOffsets{}
	modules := goAutoSDKActivationTestModules()
	elfFile := &elf.File{FileHeader: elf.FileHeader{
		Class:   elf.ELFCLASS64,
		Machine: elf.EM_X86_64,
	}}

	setGoAutoSDKActivationSupport(offsets, modules, elfFile)
	assert.Equal(t, uint64(1), offsets[AutoSDKActivationSupported])

	modules.invalid = true
	setGoAutoSDKActivationSupport(offsets, modules, elfFile)
	assert.Equal(t, uint64(0), offsets[AutoSDKActivationSupported])

	modules.invalid = false
	modules.sums["go.opentelemetry.io/auto/sdk"] = "h1:"
	setGoAutoSDKActivationSupport(offsets, modules, elfFile)
	assert.Equal(t, uint64(0), offsets[AutoSDKActivationSupported])
}

func TestSetGoAutoSDKActivationSupportRequiresSupportedArchitecture(t *testing.T) {
	modules := goAutoSDKActivationTestModules()
	tests := []struct {
		name    string
		class   elf.Class
		machine elf.Machine
		want    uint64
	}{
		{name: "amd64", class: elf.ELFCLASS64, machine: elf.EM_X86_64, want: 1},
		{name: "arm64", class: elf.ELFCLASS64, machine: elf.EM_AARCH64, want: 1},
		{name: "386", class: elf.ELFCLASS32, machine: elf.EM_386},
		{name: "32_bit_x86_64", class: elf.ELFCLASS32, machine: elf.EM_X86_64},
		{name: "ppc64", class: elf.ELFCLASS64, machine: elf.EM_PPC64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := FieldOffsets{AutoSDKActivationSupported: 1}
			elfFile := &elf.File{FileHeader: elf.FileHeader{
				Class:   tt.class,
				Machine: tt.machine,
			}}

			setGoAutoSDKActivationSupport(offsets, modules, elfFile)

			assert.Equal(t, tt.want, offsets[AutoSDKActivationSupported])
		})
	}
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

func TestPrefetchedGoRuntimeGoroutineOffsets(t *testing.T) {
	track, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	tests := []struct {
		structName string
		fieldName  string
		goVersion  string
		want       uint64
	}{
		{structName: "runtime.gList", fieldName: "size", goVersion: "1.25.0", want: 8},
		{structName: "runtime.mutex", fieldName: "key", goVersion: "1.17.0", want: 0},
		{structName: "runtime.p", fieldName: "gFree", goVersion: "1.17.0", want: 3584},
		{structName: "runtime.p", fieldName: "gFree", goVersion: "1.18.0", want: 2464},
		{structName: "runtime.p", fieldName: "gFree", goVersion: "1.23.0", want: 2456},
		{structName: "runtime.p", fieldName: "gFree", goVersion: "1.26.0", want: 2464},
		{structName: "runtime.schedt", fieldName: "gFree", goVersion: "1.17.0", want: 152},
		{structName: "runtime.schedt", fieldName: "gFree", goVersion: "1.20.0", want: 160},
		{structName: "runtime.schedt", fieldName: "gFree", goVersion: "1.25.0", want: 168},
		{structName: "runtime.schedt", fieldName: "gFree", goVersion: "1.26.0", want: 184},
		{structName: "runtime.schedt", fieldName: "ngsys", goVersion: "1.17.0", want: 72},
		{structName: "runtime.schedt", fieldName: "ngsys", goVersion: "1.25.0", want: 80},
		{structName: "runtime.schedt", fieldName: "ngsys", goVersion: "1.26.0", want: 96},
	}

	for _, tt := range tests {
		t.Run(tt.structName+"."+tt.fieldName+"/"+tt.goVersion, func(t *testing.T) {
			assertPrefetchedOffset(t, track, tt.structName, tt.fieldName, tt.goVersion, tt.want)
		})
	}

	_, found := track.Find("runtime.gList", "size", "1.24.0")
	assert.False(t, found, "runtime.gList.size should be unavailable before Go 1.25")
}

func TestPrefetchedGoRuntimeGCGoalFieldOffsets(t *testing.T) {
	track, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	for _, tt := range []struct {
		goVersion string
		want      uint64
	}{
		{goVersion: "1.17.0", want: 32},
		{goVersion: "1.17.13", want: 32},
		{goVersion: "1.18.0", want: 104},
		{goVersion: "1.18.10", want: 104},
	} {
		offset, found := prefetchedGoRuntimeGCGoalOffset(track, tt.goVersion)
		require.True(t, found, "heapGoal missing for Go %s", tt.goVersion)
		assert.Equal(t, tt.want, offset)
	}
	_, found := prefetchedGoRuntimeGCGoalOffset(track, "1.19.0")
	assert.False(t, found)

	heapGoal := track.Data["runtime.gcControllerState"]["heapGoal"]
	assert.Equal(t, "1.17.0", heapGoal.Versions.Oldest)
	assert.Equal(t, "1.18.10", heapGoal.Versions.Newest)
}

func TestResolveNestedStructPrefetchedOffsetsLogsMissingFields(t *testing.T) {
	const goVersion = "1.25.0"
	for _, missing := range []struct {
		structName string
		fieldName  string
	}{
		{structName: "runtime.schedt", fieldName: "gFree"},
		{structName: "runtime.mutex", fieldName: "key"},
		{structName: "runtime.gList", fieldName: "size"},
	} {
		t.Run(missing.structName+"."+missing.fieldName, func(t *testing.T) {
			track, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
			require.NoError(t, err)
			delete(track.Data[missing.structName], missing.fieldName)

			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(
				&logs,
				&slog.HandlerOptions{Level: slog.LevelDebug},
			))
			resolveNestedStructPreFetchedOffsets(track, FieldOffsets{}, goVersion, logger)

			assert.Contains(t, logs.String(), "missing_field="+missing.structName+"."+missing.fieldName)
			assert.Contains(t, logs.String(), "go_version="+goVersion)
		})
	}
}

func assertPrefetchedOffset(
	t *testing.T,
	track *offsets.Track,
	structName string,
	fieldName string,
	goVersion string,
	want uint64,
) {
	t.Helper()
	offset, found := track.Find(structName, fieldName, goVersion)
	require.True(t, found, "%s.%s missing for Go %s", structName, fieldName, goVersion)
	assert.Equal(t, want, offset, "%s.%s Go %s offset", structName, fieldName, goVersion)
}

func TestPrefetchedGoRuntimeHistogramOffsets(t *testing.T) {
	track, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	for _, fieldName := range []string{"timeToRun"} {
		_, found := track.Find("runtime.schedt", fieldName, "1.19.13")
		assert.False(t, found, "%s should be unavailable before Go 1.20", fieldName)
		_, found = track.Find("runtime.schedt", fieldName, "1.20.0")
		assert.True(t, found, "%s missing for Go 1.20", fieldName)
	}

	_, found := track.Find("runtime.schedt", "stwTotalTimeGC", "1.21.13")
	assert.False(t, found, "stwTotalTimeGC should be unavailable before Go 1.22")
	_, found = track.Find("runtime.schedt", "stwTotalTimeGC", "1.22.0")
	assert.True(t, found, "stwTotalTimeGC missing for Go 1.22")

	for _, goVersion := range []string{"1.20.0", "1.22.0", "1.26.0"} {
		underflow, underflowFound := track.Find("runtime.timeHistogram", "underflow", goVersion)
		overflow, overflowFound := track.Find("runtime.timeHistogram", "overflow", goVersion)
		require.True(t, underflowFound, "underflow missing for Go %s", goVersion)
		require.True(t, overflowFound, "overflow missing for Go %s", goVersion)
		assert.Equal(t, uint64(1280), underflow, "underflow offset for Go %s", goVersion)
		assert.Equal(t, underflow+uint64(8), overflow, "overflow offset for Go %s", goVersion)
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
