// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustabi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatabaseRoundTripFromCompilerOnlyJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rust-offsets.json")
	legacy := []byte(`{
  "profiles": [
    {
      "Arch": "amd64",
      "Rustc": "1.99.0",
      "CompilerCommit": "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4"
    }
  ]
}
`)
	require.NoError(t, os.WriteFile(path, legacy, 0o600))

	database, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, Database{Profiles: []Profile{{
		Arch: "amd64", Rustc: "1.99.0", CompilerCommit: "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4",
	}}}, database)

	profile := Profile{
		Arch: "arm64", Rustc: "1.100.0",
		CrateSets: []CrateVersions{{"tokio": {"1.48.0"}, "hyper": {"1.7.0"}}},
		Config:    Layouts{VecPtr: 8, VecLen: 16, HTTP1: 1},
		Channels: map[string]MessageLayout{
			"hyper::client::dispatch::Envelope<Request>": {ListHead: 8, TxPointer: 24, Request: true},
		},
		CompilerCommit: "0ef1bc386059596dada8fb65b50425aab2ea637a",
	}
	database.Add(profile)
	require.NoError(t, database.Write(path))

	reloaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, database, reloaded)
	require.Contains(t, reloaded.Profiles, Profile{
		Arch: "amd64", Rustc: "1.99.0", CompilerCommit: "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4",
	})
	require.Contains(t, reloaded.Profiles, profile)
}

func TestDatabaseWriteDeterministicForReorderedCrateSets(t *testing.T) {
	first := CrateVersions{"hyper": {"1.7.0"}, "tokio": {"0.2.25", "1.48.0"}}
	second := CrateVersions{"hyper": {"1.8.0"}, "tokio": {"1.49.0"}}
	reorderedFirst := CrateVersions{"tokio": {"1.48.0", "0.2.25"}, "hyper": {"1.7.0"}}
	reorderedSecond := CrateVersions{"tokio": {"1.49.0"}, "hyper": {"1.8.0"}}
	compilerOnly := Profile{Arch: "amd64", Rustc: "1.99.0", CompilerCommit: "compiler"}
	measured := Profile{
		Arch: "amd64", Rustc: "1.100.0", Config: Layouts{VecPtr: 8},
		Channels: map[string]MessageLayout{"envelope": {TxTag: 16}},
	}

	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.json")
	secondPath := filepath.Join(dir, "second.json")
	var firstDB Database
	firstDB.Add(compilerOnly)
	measured.CrateSets = []CrateVersions{first, second}
	firstDB.Add(measured)
	require.NoError(t, firstDB.Write(firstPath))

	var secondDB Database
	measured.CrateSets = []CrateVersions{reorderedSecond, reorderedFirst}
	secondDB.Add(measured)
	secondDB.Add(compilerOnly)
	require.NoError(t, secondDB.Write(secondPath))

	firstOutput, err := os.ReadFile(firstPath)
	require.NoError(t, err)
	secondOutput, err := os.ReadFile(secondPath)
	require.NoError(t, err)
	require.Equal(t, firstOutput, secondOutput)
}

func TestDatabaseWriteFailurePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rust-offsets.json")
	original := []byte("{\n  \"profiles\": []\n}\n")
	originalPath := filepath.Join(dir, "original.json")
	require.NoError(t, os.WriteFile(originalPath, original, 0o600))

	require.NoError(t, os.Mkdir(path, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(path, "keep"), []byte("destination is not empty"), 0o600))

	database := Database{Profiles: []Profile{{Arch: "amd64", Rustc: "1.100.0"}}}
	err := database.Write(path)
	require.Error(t, err)
	contents, readErr := os.ReadFile(originalPath)
	require.NoError(t, readErr)
	require.Equal(t, original, contents)
	temporary, globErr := filepath.Glob(filepath.Join(dir, ".rust-offsets-*"))
	require.NoError(t, globErr)
	require.Empty(t, temporary)
}

func TestDatabasePreservesCrateSets(t *testing.T) {
	first := CrateVersions{"hyper": {"1.7.0"}, "tokio": {"0.2.25", "1.48.0"}}
	second := CrateVersions{"hyper": {"1.8.0"}, "tokio": {"1.49.0"}}
	reordered := CrateVersions{"hyper": {"1.7.0"}, "tokio": {"1.48.0", "0.2.25"}}

	var db Database
	for _, crates := range []CrateVersions{first, second, reordered} {
		db.Add(Profile{Arch: "amd64", Rustc: "1.99.0", Config: Layouts{VecPtr: 8}, CrateSets: []CrateVersions{crates}})
	}
	require.Len(t, db.Profiles, 1)
	require.ElementsMatch(t, []CrateVersions{first, second}, db.Profiles[0].CrateSets)
}

func TestDatabasePreservesCompilerCommits(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
		profiles            int
	}{
		{"different commits", "first", "second", 2},
		{"same commit", "first", "first", 1},
		{"fill missing commit", "", "second", 1},
		{"keep known commit", "first", "", 1},
		{"both commits missing", "", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var database Database
			for _, commit := range []string{tc.first, tc.second} {
				database.Add(Profile{
					Arch: "amd64", Rustc: "1.99.0", CompilerCommit: commit,
					Config: Layouts{VecPtr: 8},
				})
			}
			require.Len(t, database.Profiles, tc.profiles)

			path := filepath.Join(t.TempDir(), "offsets.json")
			require.NoError(t, database.Write(path))
			reloaded, err := Load(path)
			require.NoError(t, err)
			require.Equal(t, database, reloaded)

			for _, commit := range []string{tc.first, tc.second} {
				if commit == "" {
					continue
				}
				build := Build{Arch: "amd64", CompilerCommit: commit}
				require.Equal(t, "1.99.0", reloaded.InferBuild(build).Rustc)
				require.NoError(t, reloaded.CheckCompiler(build))
			}
		})
	}
}
