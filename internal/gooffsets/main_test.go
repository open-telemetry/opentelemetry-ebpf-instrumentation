// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/grafana/go-offsets-tracker/pkg/binary"
	"github.com/grafana/go-offsets-tracker/pkg/offsets"
	"github.com/grafana/go-offsets-tracker/pkg/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCoverage(t *testing.T) {
	queries := []query{
		{outputType: "internal/abi.Type", outputField: "TFlag"},
		{outputType: "internal/abi.Type", outputField: sizeField},
	}
	track := coverageTrack(queries, offsets.VersionInfo{Oldest: "1.27.0", Newest: "1.27.1"})
	require.NoError(t, validateCoverage(track, queries))

	fact := track.Data["runtime.moduledata"]["itabsize"]
	fact.Versions.Newest = "1.27.0"
	track.Data["runtime.moduledata"]["itabsize"] = fact
	require.ErrorContains(t, validateCoverage(track, queries), "runtime.moduledata.itabsize has coverage")
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

	queries := []query{{outputType: "internal/abi.Type", outputField: "TFlag"}}
	result := generatedResult("internal/abi.Type", "TFlag")
	require.ErrorContains(t, writeResultsAtomic(output, queries, []*target.Result{result}), "runtime.moduledata")

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
	queries := []query{{outputType: "internal/abi.Type", outputField: "TFlag"}}
	facts := []*binary.DataMemberOffset{
		{
			DataMember: &binary.DataMember{StructName: "internal/abi.Type", Field: "TFlag"},
			Offset:     1,
		},
	}
	for _, field := range moduledataABIFacts {
		facts = append(facts, &binary.DataMemberOffset{
			DataMember: &binary.DataMember{StructName: "runtime.moduledata", Field: field},
			Offset:     1,
		})
	}
	result := &target.Result{
		ModuleName: offsets.GoStdLib,
		ResultsByVersion: []*target.VersionedResult{
			{Version: "1.27.0", OffsetData: &binary.Result{DataMembers: facts}},
		},
	}

	require.NoError(t, writeResultsAtomic(output, queries, []*target.Result{result}))
	track, err := offsets.Open(output)
	require.NoError(t, err)
	require.NoError(t, validateCoverage(track, queries))
}

func TestGeneratedOffsetsCoverage(t *testing.T) {
	inputData, err := os.ReadFile(filepath.Join("..", "..", "configs", "offsets", "go_abi_input.json"))
	require.NoError(t, err)
	var config abiInput
	require.NoError(t, json.Unmarshal(inputData, &config))
	queries, err := buildQueries(config)
	require.NoError(t, err)

	track, err := offsets.Open(filepath.Join("..", "..", "pkg", "internal", "goexec", "offsets.json"))
	require.NoError(t, err)
	require.NoError(t, validateCoverage(track, queries))
}

func coverageTrack(queries []query, coverage offsets.VersionInfo) *offsets.Track {
	track := &offsets.Track{Data: map[string]offsets.Struct{}}
	for _, q := range queries {
		addCoverage(track, q.outputType, q.outputField, coverage)
	}
	for _, field := range moduledataABIFacts {
		addCoverage(track, "runtime.moduledata", field, coverage)
	}
	return track
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
