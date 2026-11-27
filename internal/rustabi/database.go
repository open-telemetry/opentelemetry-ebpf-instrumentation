// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// database.go builds and maintains the JSON offset database used by make update-offsets.
// It records DWARF measurements, merges equivalent profiles, and writes database
// updates atomically.

package rustabi // import "go.opentelemetry.io/obi/internal/rustabi"

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

func Inspect(path string) (Profile, error) {
	f, err := elf.Open(path)
	if err != nil {
		return Profile{}, err
	}

	defer f.Close()
	build, err := ReadCompiler(f)
	if err != nil {
		return Profile{}, err
	}

	crates, err := ReadCrates(f)
	if err != nil {
		return Profile{}, err
	}

	types, err := readRustDwarfTypes(f)
	if err != nil {
		return Profile{}, err
	}

	config, err := types.protocolLayouts()
	if err != nil {
		return Profile{}, err
	}

	channels, err := types.messageLayouts()
	if err != nil {
		return Profile{}, err
	}

	if build.Rustc == "" || config.HTTP1 == 0 {
		return Profile{}, fmt.Errorf("incomplete Rust offset fixture: %+v", build)
	}

	return Profile{
		Arch: build.Arch, Rustc: build.Rustc, CrateSets: []CrateVersions{crates}, Config: config, Channels: channels,
		CompilerCommit: build.CompilerCommit,
	}, nil
}

func Load(path string) (Database, error) {
	var database Database
	data, err := os.ReadFile(path)

	if errors.Is(err, os.ErrNotExist) {
		return database, nil
	}

	if err != nil {
		return database, err
	}

	err = json.Unmarshal(data, &database)
	return database, err
}

func (d *Database) Add(profile Profile) {
	for i := range d.Profiles {
		old := &d.Profiles[i]
		if old.Arch != profile.Arch || old.Rustc != profile.Rustc || old.Config != profile.Config || !maps.Equal(old.Channels, profile.Channels) {
			continue
		}

		for _, measured := range profile.CrateSets {
			if !slices.ContainsFunc(old.CrateSets, func(existing CrateVersions) bool {
				return maps.EqualFunc(existing, measured, sameVersions)
			}) {
				old.CrateSets = append(old.CrateSets, measured)
			}
		}

		if old.CompilerCommit == "" {
			old.CompilerCommit = profile.CompilerCommit
		}

		return
	}

	d.Profiles = append(d.Profiles, profile)
}

func compareJSON[T any](a, b T) int {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Compare(x, y)
}

func (d *Database) Write(path string) error {
	for _, profile := range d.Profiles {
		for _, measured := range profile.CrateSets {
			for _, versions := range measured {
				slices.Sort(versions)
			}
		}
		slices.SortFunc(profile.CrateSets, compareJSON[CrateVersions])
	}
	slices.SortFunc(d.Profiles, compareJSON[Profile])

	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(d); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(filepath.Dir(path), ".rust-offsets-*")
	if err != nil {
		return err
	}

	defer os.Remove(temporary.Name())

	if _, err := temporary.Write(data.Bytes()); err != nil {
		_ = temporary.Close()
		return err
	}

	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}

	if err := temporary.Close(); err != nil {
		return err
	}

	return os.Rename(temporary.Name(), path)
}
