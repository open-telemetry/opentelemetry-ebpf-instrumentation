// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	_ "embed"
	"encoding/json"
	"sync"

	"go.opentelemetry.io/obi/internal/rustabi"
)

//go:embed rust_offsets.json
var rustOffsetData []byte

// All attachments share one decoded copy of the read-only ABI database.
var rustOffsetDatabase = sync.OnceValues(func() (rustabi.Database, error) {
	var database rustabi.Database
	err := json.Unmarshal(rustOffsetData, &database)
	return database, err
})

func (e *rustExecutable) resolveABI(f *elf.File) error {
	build, err := rustabi.ReadCompiler(f)
	if err != nil {
		return err
	}
	database, err := rustOffsetDatabase()
	if err != nil {
		return err
	}
	return database.CheckCompiler(build)
}
