// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"go.opentelemetry.io/obi/internal/rustexec"
)

//go:embed rust_offsets.json
var rustOffsetData []byte

// Compiler identity records are shared across executable attachments.
var rustOffsetDatabase = sync.OnceValues(func() (rustexec.Database, error) {
	var database rustexec.Database
	err := json.Unmarshal(rustOffsetData, &database)
	return database, err
})

func checkRustCompiler(f *elf.File) error {
	build, err := rustexec.ReadBuild(f)
	if err != nil {
		return err
	}
	database, err := rustOffsetDatabase()
	if err != nil {
		return err
	}
	build = database.InferBuild(build)
	for _, compiler := range database.Profiles {
		if compiler.Arch == build.Arch && compiler.Rustc == build.Rustc {
			return nil
		}
	}
	return fmt.Errorf("unsupported Rust compiler %q on %s", build.Rustc, build.Arch)
}
