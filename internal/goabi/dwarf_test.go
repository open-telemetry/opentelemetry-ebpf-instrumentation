// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/goversion"
)

type inspectBuild struct {
	name string
	env  []string
	args []string
}

var (
	defaultInspectBuild  = inspectBuild{name: "default", env: []string{"CGO_ENABLED=0"}}
	nodwarf5InspectBuild = inspectBuild{name: "nodwarf5", env: []string{"CGO_ENABLED=0", "GOEXPERIMENT=nodwarf5"}}
	// External linking adds the C compile units of runtime/cgo to the DWARF.
	externalLinkInspectBuild = inspectBuild{
		name: "external link",
		env:  []string{"CGO_ENABLED=1"},
		args: []string{"-ldflags", "-linkmode=external"},
	}

	inspectBuilds      = map[string]inspectExecutable{}
	inspectBuildsMutex sync.Mutex
)

type inspectExecutable struct {
	data          *dwarf.Data
	targetVersion goversion.Version
	err           error
}

// inspectDWARF builds configs/offsets/std_inspect.go once per build for the
// whole test package and returns its DWARF and Go version.
func inspectDWARF(t *testing.T, build inspectBuild) (*dwarf.Data, goversion.Version) {
	t.Helper()
	if build.name == externalLinkInspectBuild.name {
		if _, err := exec.LookPath("gcc"); runtime.GOOS != "linux" || err != nil {
			t.Skip("external linking needs a native Linux C toolchain")
		}
	}

	inspectBuildsMutex.Lock()
	defer inspectBuildsMutex.Unlock()
	executable, built := inspectBuilds[build.name]
	if !built {
		executable = buildInspectExecutable(t, build)
		inspectBuilds[build.name] = executable
	}
	if executable.err != nil && slices.Contains(build.env, "GOEXPERIMENT=nodwarf5") {
		t.Skipf("the toolchain does not build with GOEXPERIMENT=nodwarf5: %v", executable.err)
	}
	require.NoError(t, executable.err)
	return executable.data, executable.targetVersion
}

func buildInspectExecutable(t *testing.T, build inspectBuild) inspectExecutable {
	t.Helper()
	executable := filepath.Join(t.TempDir(), "inspect")
	source := filepath.Join("..", "..", "configs", "offsets", "std_inspect.go")
	args := append([]string{"build", "-buildvcs=false"}, build.args...)
	cmd := exec.Command("go", append(args, "-o", executable, source)...)
	cmd.Env = append(append(os.Environ(), "GOOS=linux"), build.env...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return inspectExecutable{err: fmt.Errorf("%w: %s", err, output)}
	}

	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		return inspectExecutable{err: err}
	}
	targetVersion, err := goversion.Parse(info.GoVersion)
	if err != nil {
		return inspectExecutable{err: err}
	}

	file, err := elf.Open(executable)
	if err != nil {
		return inspectExecutable{err: err}
	}
	defer file.Close()
	// DWARF copies the debug sections, so the data outlives the file.
	data, err := file.DWARF()
	return inspectExecutable{data: data, targetVersion: targetVersion, err: err}
}

func TestExtractCompleteRuntimeABI(t *testing.T) {
	data, targetVersion := inspectDWARF(t, defaultInspectBuild)

	abi, err := Extract(data, targetVersion)
	require.NoError(t, err)
	requirements, err := Requirements(targetVersion)
	require.NoError(t, err)
	assert.Len(t, abi.Facts(), len(requirements))
	if targetVersion.Compare(go127) < 0 {
		assert.Nil(t, abi.TypeMetadata)
		return
	}
	require.NotNil(t, abi.TypeMetadata)
	assert.Equal(t, uint64(0), abi.TypeMetadata.ITabInterOffset)

	legacyABI, err := Extract(data, goversion.MustParse("go1.26.9"))
	require.NoError(t, err)
	assert.Nil(t, legacyABI.TypeMetadata)
	assert.Len(t, legacyABI.Facts(), 6)
}

func TestStoreValueRejectsConflicts(t *testing.T) {
	values := map[string]uint64{"fact": 1}
	require.NoError(t, storeValue(values, "fact", 1))
	require.ErrorContains(t, storeValue(values, "fact", 2), "conflicting values")
}

func TestReadDWARFFromDefiningUnitsMatchesFullWalk(t *testing.T) {
	for _, build := range []inspectBuild{defaultInspectBuild, nodwarf5InspectBuild, externalLinkInspectBuild} {
		t.Run(build.name, func(t *testing.T) {
			data, targetVersion := inspectDWARF(t, build)
			requested, err := requiredDefinitions(targetVersion)
			require.NoError(t, err)

			units := definingUnits(requested)
			assert.Contains(t, units, RuntimeUnit)
			if targetVersion.Compare(go127) >= 0 {
				assert.Contains(t, units, "internal/abi")
			}
			values, err := readDWARF(data, requested, units)
			require.NoError(t, err)
			fullValues, err := readDWARF(data, requested, nil)
			require.NoError(t, err)
			assert.Equal(t, fullValues, values)

			// The defining units alone must be enough, without the full walk fallback.
			abi, err := extractFromUnits(data, requested, units)
			require.NoError(t, err)
			assert.Len(t, abi.Facts(), len(requested))
		})
	}
}

func TestExtractFallsBackToFullWalk(t *testing.T) {
	data, targetVersion := inspectDWARF(t, defaultInspectBuild)
	requested, err := requiredDefinitions(targetVersion)
	require.NoError(t, err)
	missingUnits := map[string]bool{"no/such/unit": true}

	_, err = extractFromUnits(data, requested, missingUnits)
	require.ErrorContains(t, err, "not found")

	abi, err := extractFromUnitsOrAll(data, requested, missingUnits)
	require.NoError(t, err)
	fullABI, err := extractFromUnits(data, requested, nil)
	require.NoError(t, err)
	assert.Equal(t, fullABI, abi)
}

func TestConstantQueryUnit(t *testing.T) {
	for constant, unit := range map[string]string{
		"internal/abi.TFlagUncommon": "internal/abi",
		"runtime.pageSize":           "runtime",
		"gopkg.in/yaml.v3.Kind":      "gopkg.in/yaml.v3",
		"noPackage":                  "",
	} {
		assert.Equal(t, unit, constantQuery{constantName: constant}.unit(), constant)
	}
}
