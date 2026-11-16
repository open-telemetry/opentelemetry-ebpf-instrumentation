// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	procSelfFDInfo  = "/proc/self/fdinfo"
	fdinfoProgramID = "prog_id:"
)

func ownedProgramIDs(fdinfoDir string) ([]ebpf.ProgramID, error) {
	entries, err := os.ReadDir(fdinfoDir)
	if err != nil {
		return nil, err
	}

	ids := make(map[ebpf.ProgramID]struct{})
	for _, entry := range entries {
		// The fdinfo of a program, and of a link, carries the program ID.
		id, ok := fdinfoID(filepath.Join(fdinfoDir, entry.Name()), fdinfoProgramID)
		if ok {
			ids[ebpf.ProgramID(id)] = struct{}{}
		}
	}

	return slices.Sorted(maps.Keys(ids)), nil
}

func fdinfoID(path, key string) (uint32, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		// A descriptor closed after its directory was read is skipped.
		return 0, false
	}

	for line := range strings.Lines(string(content)) {
		value, found := strings.CutPrefix(line, key)
		if !found {
			continue
		}

		id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		return uint32(id), err == nil
	}

	return 0, false
}
