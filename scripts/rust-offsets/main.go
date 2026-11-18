// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"go.opentelemetry.io/obi/internal/rustexec"
)

func main() {
	binary := flag.String("binary", "", "build-time executable containing Rust DWARF")
	output := flag.String("output", "pkg/internal/ebpf/generictracer/rust_offsets.json", "offset database")
	symbols := flag.String("symbols", "", "ordinary release executable supplying additional crate identifiers")
	flag.Parse()
	if err := inspect(*binary, *symbols, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func inspect(binary, symbols, output string) error {
	if binary == "" {
		return errors.New("-binary is required; use make update-rust-offsets to build the version matrix")
	}
	profile, err := rustexec.Inspect(binary)
	if err != nil {
		return err
	}
	if symbols != "" {
		if err := rustexec.AddSymbols(&profile, symbols); err != nil {
			return err
		}
	}
	database, err := rustexec.Load(output)
	if err != nil {
		return err
	}
	database.Add(profile)
	return database.Write(output)
}
