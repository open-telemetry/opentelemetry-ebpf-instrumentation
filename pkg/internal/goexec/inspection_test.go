// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/goabi"
	"go.opentelemetry.io/obi/internal/goversion"
	"go.opentelemetry.io/obi/internal/test/tools"
	obiexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

// The functions below run one step of InspectOffsets on its own inspection.

func instrumentationPoints(elfF *elf.File, funcNames []string) (map[string][]FuncOffsets, error) {
	return newInspection(elfF).instrumentationPoints(funcNames)
}

func structMemberOffsets(elfFile *elf.File) (FieldOffsets, error) {
	return newInspection(elfFile).structMemberOffsets()
}

func findInterfaceImpls(ef *elf.File) (map[string]uint64, error) {
	return newInspection(ef).findInterfaceImpls()
}

func loadModuledataOffsets(elfF *elf.File) (goabi.Moduledata, error) {
	abi, err := newInspection(elfF).moduledataABI()
	if err != nil {
		return goabi.Moduledata{}, err
	}
	return abi.Moduledata, nil
}

// findInterfaceImplsFromModuledata reads the interface implementations with
// the runtime ABI of targetVersion instead of the executable's own version.
func findInterfaceImplsFromModuledata(ef *elf.File, targetVersion goversion.Version) (map[string]uint64, error) {
	in := newInspection(ef)
	in.runtimeABI = sync.OnceValues(func() (goabi.ABI, error) {
		return resolveGoRuntimeABI(
			func() (goabi.ABI, error) {
				data, err := ef.DWARF()
				if err != nil {
					return goabi.ABI{}, err
				}
				return goabi.Extract(data, targetVersion)
			},
			func() (goabi.ABI, error) {
				return loadGeneratedGoRuntimeABI(targetVersion)
			},
		)
	})
	return in.moduledataInterfaceImpls()
}

var inspectionFunctions = []string{
	"net/http.serverHandler.ServeHTTP",
	"net/http.(*conn).serve",
	"net/http.(*Transport).roundTrip",
	"runtime.newproc1",
	"runtime.goexit1",
}

type pingServerBuild struct {
	name string
	env  []string
	args []string
}

var (
	defaultBuild  = pingServerBuild{name: "default", env: []string{"CGO_ENABLED=0"}}
	strippedBuild = pingServerBuild{name: "stripped"}
	nodwarf5Build = pingServerBuild{name: "nodwarf5", env: []string{"CGO_ENABLED=0", "GOEXPERIMENT=nodwarf5"}}
	// External linking adds the C compile units of runtime/cgo to the DWARF.
	externalLinkBuild = pingServerBuild{
		name: "external link",
		env:  []string{"CGO_ENABLED=1", "PATH=" + os.Getenv("PATH")},
		args: []string{"-ldflags", "-linkmode=external"},
	}

	pingServerBuilds      = map[string]*elf.File{}
	pingServerBuildErrors = map[string]error{}
	pingServerBuildsMutex sync.Mutex
)

// pingServerELF builds the ping server once per build for the whole test package.
func pingServerELF(tb testing.TB, build pingServerBuild) *elf.File {
	tb.Helper()
	if build.name == strippedBuild.name {
		return smallELF
	}
	if build.name == externalLinkBuild.name {
		if _, err := exec.LookPath("gcc"); runtime.GOOS != "linux" || err != nil {
			tb.Skip("external linking needs a native Linux C toolchain")
		}
	}

	pingServerBuildsMutex.Lock()
	defer pingServerBuildsMutex.Unlock()
	file, built := pingServerBuilds[build.name]
	err := pingServerBuildErrors[build.name]
	if !built && err == nil {
		file, err = compileELFWithEnv(tools.ProjectDir()+"/internal/test/cmd/pingserver/server.go", build.env, build.args...)
		pingServerBuilds[build.name], pingServerBuildErrors[build.name] = file, err
	}
	if err != nil && slices.Contains(build.env, "GOEXPERIMENT=nodwarf5") {
		tb.Skipf("the toolchain does not build with GOEXPERIMENT=nodwarf5: %v", err)
	}
	require.NoError(tb, err)
	return file
}

func TestStructMemberOffsetsFromRuntimeUnitMatchFullWalk(t *testing.T) {
	check := func(t *testing.T, data *dwarf.Data) {
		t.Helper()
		offsets, missing, found := structMemberOffsetsFromUnit(data, goabi.RuntimeUnit)
		require.True(t, found, "the runtime compile unit holds no library struct of structMembers")
		fullOffsets, fullMissing, _ := structMemberOffsetsFromUnit(data, "")
		assert.NotEmpty(t, offsets)
		assert.Equal(t, fullOffsets, offsets)
		assert.Equal(t, fullMissing, missing)
	}

	for name, data := range map[string]*dwarf.Data{
		"pingserver": debugData,
		"grpc":       grpcElf,
		"oteltrace":  spanContextData,
		"autosdk":    autoSDKSpanData,
	} {
		t.Run(name, func(t *testing.T) { check(t, data) })
	}
	t.Run(nodwarf5Build.name, func(t *testing.T) {
		data, err := pingServerELF(t, nodwarf5Build).DWARF()
		require.NoError(t, err)
		check(t, data)
	})
	t.Run(externalLinkBuild.name, func(t *testing.T) {
		data, err := pingServerELF(t, externalLinkBuild).DWARF()
		require.NoError(t, err)
		require.True(t, hasForeignCompileUnit(t, data), "no C compile unit to skip")
		check(t, data)
	})
}

// dwarfLanguageGo is DW_LANG_Go, which debug/dwarf does not define.
const dwarfLanguageGo = 0x16

func hasForeignCompileUnit(t *testing.T, data *dwarf.Data) bool {
	t.Helper()
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		require.NoError(t, err)
		if entry == nil {
			return false
		}
		if entry.Tag != dwarf.TagCompileUnit {
			continue
		}
		if language, _ := entry.Val(dwarf.AttrLanguage).(int64); language != dwarfLanguageGo {
			return true
		}
		reader.SkipChildren()
	}
}

func TestStructMemberOffsetsFallBackToFullWalk(t *testing.T) {
	offsets, missing, found := structMemberOffsetsFromUnit(debugData, "no/such/unit")
	assert.False(t, found)
	assert.Empty(t, offsets)
	assert.NotEmpty(t, missing)

	fullOffsets, fullMissing, _ := structMemberOffsetsFromUnit(debugData, "")
	offsets, missing = structMemberOffsetsFromUnitOrAll(debugData, "no/such/unit")
	assert.NotEmpty(t, offsets)
	assert.Equal(t, fullOffsets, offsets)
	assert.Equal(t, fullMissing, missing)
}

func TestInspectOffsetsLoadsDWARFOnce(t *testing.T) {
	for _, build := range []pingServerBuild{defaultBuild, strippedBuild, nodwarf5Build} {
		t.Run(build.name, func(t *testing.T) {
			file := pingServerELF(t, build)
			in, loads := countingInspection(file)

			_, err := inspectOffsets(obiexec.New(obiexec.Init{ELF: file}), in, inspectionFunctions)
			require.NoError(t, err)
			assert.Equal(t, 1, *loads)
		})
	}

	for name, file := range map[string]*elf.File{
		"no .gopclntab":      emptyELF(t),
		"no Go build info":   buildTestELF(t, testGopclntabVMA),
		"unknown Go version": buildTestELF(t, testGopclntabVMA, "unknown"),
	} {
		t.Run(name, func(t *testing.T) {
			in, loads := countingInspection(file)

			_, err := inspectOffsets(obiexec.New(obiexec.Init{ELF: file}), in, inspectionFunctions)
			require.Error(t, err)
			assert.Zero(t, *loads)
		})
	}
}

func TestRuntimeABIRejectsGoVersionWithoutTypeMetadata(t *testing.T) {
	in := newInspection(buildTestELF(t, testGopclntabVMA, "go1.26.4"))
	in.loadDWARF = func() (*dwarf.Data, error) { return debugData, nil }

	_, err := in.runtimeABI()
	require.ErrorContains(t, err, "no runtime type metadata ABI")
}

// TestRuntimeTextBaseSkipsStructMemberOffsets checks that GoSymbolResolver
// finds the same moduledata as a full inspection without walking DWARF for
// the struct member offsets, which it does not use.
func TestRuntimeTextBaseSkipsStructMemberOffsets(t *testing.T) {
	// structMemberOffsetsFromUnit logs with this attribute when it starts a walk.
	const walk = "function=structMemberOffsetsFromDwarf"
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	for _, build := range []pingServerBuild{defaultBuild, strippedBuild, nodwarf5Build} {
		t.Run(build.name, func(t *testing.T) {
			file := pingServerELF(t, build)

			logs.Reset()
			full := newInspection(file)
			want, wantErr := full.moduledata()
			if full.dwarf().err == nil {
				require.Contains(t, logs.String(), walk, "a full inspection no longer logs the walk")
			}

			logs.Reset()
			got, err := standaloneModuledata(file)
			assert.Equal(t, wantErr, err)
			assert.Equal(t, want, got)
			resolver := &GoSymbolResolver{executable: file}
			_, _ = resolver.runtimeTextBase()
			assert.NotContains(t, logs.String(), walk)
		})
	}
}

func countingInspection(file *elf.File) (*inspection, *int) {
	loads := 0
	in := newInspection(file)
	in.loadDWARF = func() (*dwarf.Data, error) {
		loads++
		return file.DWARF()
	}
	return in, &loads
}

// emptyELF returns a 64-bit ELF with no sections, like a non-Go executable
// stripped of its section headers.
func emptyELF(t *testing.T) *elf.File {
	t.Helper()
	header := make([]byte, elfHeaderSize)
	copy(header, elf.ELFMAG)
	header[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(header[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(header[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(header[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(header[52:], elfHeaderSize)

	file, err := elf.NewFile(bytes.NewReader(header))
	require.NoError(t, err)
	return file
}

// TestInspectOffsetsMatchesSeparateLookups checks that sharing one inspection
// between the InspectOffsets steps gives the same results as running each
// step on its own.
func TestInspectOffsetsMatchesSeparateLookups(t *testing.T) {
	for _, build := range []pingServerBuild{defaultBuild, strippedBuild, nodwarf5Build} {
		t.Run(build.name, func(t *testing.T) {
			file := pingServerELF(t, build)

			offsets, err := InspectOffsets(obiexec.New(obiexec.Init{ELF: file}), inspectionFunctions)
			require.NoError(t, err)

			funcs, err := instrumentationPoints(file, inspectionFunctions)
			require.NoError(t, err)
			fields, err := structMemberOffsets(file)
			require.NoError(t, err)
			itypes, err := findInterfaceImpls(file)
			require.NoError(t, err)

			assert.Equal(t, funcs, offsets.Funcs)
			assert.Equal(t, itypes, offsets.ITypes)
			assert.Equal(t, deterministicFieldOffsets(fields), deterministicFieldOffsets(offsets.Field))
		})
	}
}

// deterministicFieldOffsets drops the constants that more than one struct in
// structMembers resolves: the generated offsets table fills them in map
// iteration order, so they can differ between two lookups on the same file.
func deterministicFieldOffsets(offsets FieldOffsets) FieldOffsets {
	owners := map[GoOffset]int{}
	for _, info := range structMembers {
		for _, constant := range info.fields {
			owners[constant]++
		}
	}

	result := FieldOffsets{}
	for constant, value := range offsets {
		if owners[constant] <= 1 {
			result[constant] = value
		}
	}
	return result
}

func BenchmarkInspectOffsets(b *testing.B) {
	file := pingServerELF(b, defaultBuild)
	info := obiexec.New(obiexec.Init{ELF: file})

	b.ReportAllocs()
	for b.Loop() {
		_, err := InspectOffsets(info, inspectionFunctions)
		require.NoError(b, err)
	}
}
