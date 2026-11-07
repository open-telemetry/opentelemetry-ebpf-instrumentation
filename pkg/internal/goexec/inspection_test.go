// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/dwarf"
	"debug/elf"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/tools"
)

type pingServerBuild struct {
	name string
	env  []string
	args []string
}

var (
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
		offsets, missing, found := structMemberOffsetsFromUnit(data, runtimeCompileUnit)
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
