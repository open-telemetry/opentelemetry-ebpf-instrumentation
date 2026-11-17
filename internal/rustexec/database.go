// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// database.go builds and maintains the JSON offset database used by make update-offsets.
// It combines DWARF measurements with release-binary crate fingerprints, merges
// equivalent profiles, and writes database updates atomically.

package rustexec // import "go.opentelemetry.io/obi/internal/rustexec"

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
	build, err := ReadBuild(f)
	if err != nil {
		return Profile{}, err
	}

	config, err := inspectRustProtocolLayouts(f)
	if err != nil {
		return Profile{}, err
	}

	channels, err := inspectRustMessages(f)
	if err != nil {
		return Profile{}, err
	}

	if build.Rustc == "" || config.HTTP1 == 0 || config.HTTP2 == 0 {
		return Profile{}, fmt.Errorf("incomplete Rust offset fixture: %+v", build)
	}

	symbols := map[string]map[string]string{}
	for name, ids := range build.CrateIDs {
		if len(build.Crates[name]) != 1 {
			continue
		}

		symbols[name] = map[string]string{}
		for _, id := range ids {
			symbols[name][id] = build.Crates[name][0]
		}
	}

	return Profile{
		Arch: build.Arch, Rustc: build.Rustc, Crates: build.Crates, Config: config, Channels: channels,
		CompilerCommit: build.CompilerCommit, CrateSymbols: symbols,
	}, nil
}

func AddSymbols(profile *Profile, path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}

	defer f.Close()

	build, err := ReadBuild(f)
	if err != nil {
		return err
	}

	if build.Arch != profile.Arch || build.Rustc != profile.Rustc {
		return errors.New("release symbols and DWARF fixture have different compiler/architecture identities")
	}

	if profile.CrateSymbols == nil {
		profile.CrateSymbols = map[string]map[string]string{}
	}

	for name, ids := range build.CrateIDs {
		if len(build.Crates[name]) != 1 {
			continue
		}

		version := build.Crates[name][0]
		if !slices.Contains(profile.Crates[name], version) {
			return fmt.Errorf("release symbols contain unexpected %s %s", name, version)
		}

		if profile.CrateSymbols[name] == nil {
			profile.CrateSymbols[name] = map[string]string{}
		}

		for _, id := range ids {
			profile.CrateSymbols[name][id] = version
		}
	}

	return nil
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
		a, _ := json.Marshal(old.Channels)
		b, _ := json.Marshal(profile.Channels)

		if old.Arch != profile.Arch || old.Rustc != profile.Rustc || old.Config != profile.Config || !bytes.Equal(a, b) {
			continue
		}

		for name, versions := range profile.Crates {
			old.Crates[name] = append(old.Crates[name], versions...)
			slices.Sort(old.Crates[name])
			old.Crates[name] = slices.Compact(old.Crates[name])
		}

		if old.CompilerCommit == "" {
			old.CompilerCommit = profile.CompilerCommit
		}

		if old.CrateSymbols == nil {
			old.CrateSymbols = map[string]map[string]string{}
		}

		for name, ids := range profile.CrateSymbols {
			if old.CrateSymbols[name] == nil {
				old.CrateSymbols[name] = map[string]string{}
			}
			maps.Copy(old.CrateSymbols[name], ids)
		}

		return
	}

	d.Profiles = append(d.Profiles, profile)
}

func (d *Database) Write(path string) error {
	slices.SortFunc(d.Profiles, func(a, b Profile) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return bytes.Compare(x, y)
	})

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
