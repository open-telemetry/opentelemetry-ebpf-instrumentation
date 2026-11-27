// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package harvest

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPythonRoutesDoesNotBlockOnAFIFORecord(t *testing.T) {
	app := t.TempDir()
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/items/{item_id}")
`)
	distInfo := filepath.Join(app, "dep-1.0.dist-info")
	require.NoError(t, os.MkdirAll(distInfo, 0o755))
	require.NoError(t, syscall.Mkfifo(filepath.Join(distInfo, "RECORD"), 0o644))

	done := make(chan *RouteHarvesterResult, 1)
	go func() {
		result, err := extractPythonRoutes(t.Context(), app, app)
		assert.NoError(t, err)
		done <- result
	}()

	select {
	case result := <-done:
		assert.Equal(t, []string{"/items/{item_id}"}, result.Routes)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "route harvesting blocked on a FIFO RECORD")
	}
}
