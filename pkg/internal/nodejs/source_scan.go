// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
)

// sigusr1Quoted contains the patterns we search for in source files to detect
// SIGUSR1 handler registration. We look for the string SIGUSR1 wrapped in
// quotes (single, double, or backtick) to avoid matching comments or logs.
var sigusr1Quoted = []string{`"SIGUSR1"`, `'SIGUSR1'`, "`SIGUSR1`"}

// sourceHasSIGUSR1Reference scans the Node.js application's source files for
// references to "SIGUSR1", 'SIGUSR1', or `SIGUSR1`. This is a fallback
// detection method used when the symbol-based detection fails (e.g. stripped
// binaries with dynamic libuv). It reuses the same directory discovery and
// file walking logic as the Node.js route harvester.
//
// Returns true if any source file contains a quoted SIGUSR1 reference.
// Returns false on any error or if no reference is found.
func sourceHasSIGUSR1Reference(pid int) bool {
	dir, err := harvest.FindAppDir(app.PID(pid))
	if err != nil {
		return false
	}

	return dirHasSIGUSR1Reference(dir)
}

// dirHasSIGUSR1Reference scans JS/TS source files in the given directory for
// quoted SIGUSR1 references.
func dirHasSIGUSR1Reference(dir string) bool {
	found := false

	_ = harvest.WalkJSFiles(dir, func(path string) error {
		_ = harvest.ScanJSFileLines(path, func(line string) bool {
			for _, pattern := range sigusr1Quoted {
				if strings.Contains(line, pattern) {
					found = true
					return true
				}
			}
			return false
		})
		if found {
			return filepath.SkipAll
		}
		return nil
	})

	return found
}
