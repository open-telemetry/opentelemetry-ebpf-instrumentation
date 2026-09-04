// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/grafana/go-offsets-tracker/pkg/binary"
	"github.com/grafana/go-offsets-tracker/pkg/offsets"
	"github.com/grafana/go-offsets-tracker/pkg/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/goabi"
)

func TestValidateCoverage(t *testing.T) {
	track := coverageTrack(t)
	require.NoError(t, validateCoverage(track))

	fact := track.Data["runtime.moduledata"]["itabsize"]
	fact.Versions.Newest = "1.27.0"
	track.Data["runtime.moduledata"]["itabsize"] = fact
	require.ErrorContains(t, validateCoverage(track), "runtime.moduledata.itabsize has coverage")
}

func TestCachedFactsRejectInvalidABI(t *testing.T) {
	track := coverageTrack(t)
	definitions, err := goabi.Definitions("go1.27.0")
	require.NoError(t, err)

	_, ok := cachedFacts(track, "1.27.0", definitions)
	assert.False(t, ok)
}

func TestGroupFieldsByVersion(t *testing.T) {
	groups, err := groupFieldsByVersion(map[string][]string{
		"runtime.moduledata": {"pcHeader", "[1.27.0]types", "[1.17.0,1.26.99]legacy"},
	})
	require.NoError(t, err)
	require.Len(t, groups, 3)
	assert.Equal(t, fieldGroup{
		fields: map[string][]string{"runtime.moduledata": {"pcHeader"}},
	}, groups[0])
	assert.Equal(t, fieldGroup{
		minimum: "1.17.0",
		maximum: "1.26.99",
		fields:  map[string][]string{"runtime.moduledata": {"legacy"}},
	}, groups[1])
	assert.Equal(t, fieldGroup{
		minimum: "1.27.0",
		fields:  map[string][]string{"runtime.moduledata": {"types"}},
	}, groups[2])
}

func TestIsolateTemporaryDirectory(t *testing.T) {
	previous, existed := os.LookupEnv("TMPDIR")
	cleanup, err := isolateTemporaryDirectory()
	require.NoError(t, err)
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = cleanup()
		}
	})
	directory := os.Getenv("TMPDIR")
	require.DirExists(t, directory)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "temporary"), []byte("data"), 0o600))

	require.NoError(t, cleanup())
	cleaned = true
	require.NoDirExists(t, directory)
	actual, actualExists := os.LookupEnv("TMPDIR")
	assert.Equal(t, existed, actualExists)
	assert.Equal(t, previous, actual)
}

func TestConfigureGoBuild(t *testing.T) {
	t.Setenv("GOFLAGS", "-mod=readonly")
	restore := configureGoBuild()
	assert.Equal(t, "-mod=readonly -buildvcs=false -tags=http2legacy", os.Getenv("GOFLAGS"))

	restore()
	assert.Equal(t, "-mod=readonly", os.Getenv("GOFLAGS"))
}

func TestValidateDistinctResults(t *testing.T) {
	first := generatedResult("runtime.moduledata", "types")
	second := generatedResult("internal/abi.Type", "TFlag")
	require.NoError(t, validateDistinctResults([]*target.Result{first, second}))

	duplicate := generatedResult("runtime.moduledata", "types")
	require.ErrorContains(
		t,
		validateDistinctResults([]*target.Result{first, duplicate}),
		"runtime.moduledata.types is produced by multiple collectors",
	)
}

func TestWriteResultsAtomicPreservesOutputOnValidationFailure(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "offsets.json")
	require.NoError(t, os.WriteFile(output, []byte("original"), 0o600))

	result := generatedResult("internal/abi.Type", "TFlag")
	require.ErrorContains(t, writeResultsAtomic(output, []*target.Result{result}), "generated type")

	contents, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, "original", string(contents))
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestWriteResultsAtomicPublishesMatchingCoverage(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "offsets.json")
	result := generatedABIResult(t)

	require.NoError(t, writeResultsAtomic(output, []*target.Result{result}))
	track, err := offsets.Open(output)
	require.NoError(t, err)
	require.NoError(t, validateCoverage(track))
}

func TestGeneratedOffsetsCoverage(t *testing.T) {
	track, err := offsets.Open(filepath.Join("..", "..", "pkg", "internal", "goexec", "offsets.json"))
	require.NoError(t, err)
	require.NoError(t, validateCoverage(track))
}

func coverageTrack(t *testing.T) *offsets.Track {
	t.Helper()
	track := &offsets.Track{Data: map[string]offsets.Struct{}}
	definitions, err := goabi.Definitions("go999.0.0")
	require.NoError(t, err)
	for _, definition := range definitions {
		addCoverage(track, definition.OutputType, definition.OutputField, offsets.VersionInfo{
			Oldest: definition.Since,
			Newest: "999.0.0",
		})
	}
	return track
}

func generatedABIResult(t *testing.T) *target.Result {
	t.Helper()
	result := &target.Result{ModuleName: offsets.GoStdLib}
	for _, version := range []string{"1.17.0", "1.27.0"} {
		definitions, err := goabi.Definitions(version)
		require.NoError(t, err)
		facts := make([]*binary.DataMemberOffset, 0, len(definitions))
		for _, definition := range definitions {
			facts = append(facts, &binary.DataMemberOffset{
				DataMember: &binary.DataMember{
					StructName: definition.OutputType,
					Field:      definition.OutputField,
				},
				Offset: 1,
			})
		}
		result.ResultsByVersion = append(result.ResultsByVersion, &target.VersionedResult{
			Version:    version,
			OffsetData: &binary.Result{DataMembers: facts},
		})
	}
	return result
}

func addCoverage(track *offsets.Track, typeName, factName string, coverage offsets.VersionInfo) {
	if track.Data[typeName] == nil {
		track.Data[typeName] = offsets.Struct{}
	}
	track.Data[typeName][factName] = offsets.Field{
		Versions: coverage,
		Offsets:  []offsets.Versioned{{Offset: 1, Since: coverage.Oldest}},
	}
}

func generatedResult(typeName, factName string) *target.Result {
	return &target.Result{
		ModuleName: offsets.GoStdLib,
		ResultsByVersion: []*target.VersionedResult{
			{
				Version: "1.27.0",
				OffsetData: &binary.Result{DataMembers: []*binary.DataMemberOffset{
					{
						DataMember: &binary.DataMember{StructName: typeName, Field: factName},
						Offset:     1,
					},
				}},
			},
		},
	}
}
