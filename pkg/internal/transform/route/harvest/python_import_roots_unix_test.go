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

	"go.opentelemetry.io/obi/pkg/internal/pythontools"
)

func TestExtractPythonDjangoModuleLookupsStayInTheProcessRoot(t *testing.T) {
	root := t.TempDir()
	host := t.TempDir()
	app := filepath.Join(root, "app")
	lib := filepath.Join(root, "lib")
	writeDjangoURLs(t, filepath.Join(app, "project", "urls.py"), `path("shop/", include("checkout.urls")),`)
	writePythonFile(t, filepath.Join(host, "checkout.py"), "")
	require.NoError(t, os.Symlink(filepath.Join(host, "checkout.py"), filepath.Join(app, "checkout.py")))
	writePythonFile(t, filepath.Join(lib, "checkout", "__init__.py"), "")
	writeDjangoURLs(t, filepath.Join(lib, "checkout", "urls.py"), `path("lib/", view),`)

	result, err := extractImportRootRoutes(t.Context(), root, pythontools.AppDirs{App: app, ImportRoots: []string{app, lib}}, maxPythonFiles)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/lib/"}, result.Routes)
}

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
		result, err := extractImportRoots(t, app)
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
