// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"go.opentelemetry.io/obi/internal/rustabi"
)

func main() {
	binary := flag.String("binary", "", "build-time executable containing Rust DWARF")
	output := flag.String("output", "pkg/internal/ebpf/generictracer/rust_offsets.json", "offset database")
	flag.Parse()

	if err := inspect(*binary, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func inspect(binary, output string) error {
	if binary == "" {
		return errors.New("-binary is required, for example go run ./scripts/rust-offsets -binary internal/rustabi/testdata/http1/http1.elf -output offsets.json")
	}

	profile, err := rustabi.Inspect(binary)
	if err != nil {
		return err
	}

	database, err := rustabi.Load(output)
	if err != nil {
		return err
	}

	database.Add(profile)

	return database.Write(output)
}
