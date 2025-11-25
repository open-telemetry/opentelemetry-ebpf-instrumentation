// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// successfulExtractRoutes simulates a successful route extraction
func successfulExtractRoutes(int32) (*RouteHarvesterResult, error) {
	return &RouteHarvesterResult{
		Routes: []string{"/api/users", "/api/orders"},
		Kind:   CompleteRoutes,
	}, nil
}

// errorExtractRoutes simulates an error during route extraction
func errorExtractRoutes(int32) (*RouteHarvesterResult, error) {
	return nil, errors.New("failed to connect to Java process")
}

// timeoutExtractRoutes simulates a slow operation that will timeout
func timeoutExtractRoutes(int32) (*RouteHarvesterResult, error) {
	// Sleep longer than any reasonable timeout
	time.Sleep(5 * time.Second)
	return &RouteHarvesterResult{
		Routes: []string{"/api/delayed"},
		Kind:   CompleteRoutes,
	}, nil
}

// panicExtractRoutes simulates a panic during route extraction
func panicExtractRoutes(int32) (*RouteHarvesterResult, error) {
	panic("unexpected error in java route extraction")
}

// slowButSuccessfulExtractRoutes simulates a slow but successful operation
func slowButSuccessfulExtractRoutes(int32) (*RouteHarvesterResult, error) {
	time.Sleep(50 * time.Millisecond) // Slow but within timeout
	return &RouteHarvesterResult{
		Routes: []string{"/api/slow"},
		Kind:   PartialRoutes,
	}, nil
}

// emptyResultExtractRoutes simulates successful extraction with no routes
func emptyResultExtractRoutes(int32) (*RouteHarvesterResult, error) {
	return &RouteHarvesterResult{
		Routes: []string{},
		Kind:   CompleteRoutes,
	}, nil
}

func createTestFileInfo(language svc.InstrumentableType) *exec.FileInfo {
	return &exec.FileInfo{
		Pid: 12345,
		Service: svc.Attrs{
			SDKLanguage: language,
		},
	}
}

func TestHarvestRoutes_Successful(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 1*time.Second)
	harvester.javaExtractRoutes = successfulExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableJava)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []string{"/api/users", "/api/orders"}, result.Routes)
	assert.Equal(t, CompleteRoutes, result.Kind)
}

func TestHarvestRoutes_Error(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 1*time.Second)
	harvester.javaExtractRoutes = errorExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableJava)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to connect to Java process")
}

func TestHarvestRoutes_Timeout(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 100*time.Millisecond) // Short timeout
	harvester.javaExtractRoutes = timeoutExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableJava)

	start := time.Now()
	result, err := harvester.HarvestRoutes(fileInfo)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, result)

	// Check that it's a HarvestError with timeout message
	var harvestErr *HarvestError
	require.ErrorAs(t, err, &harvestErr)
	assert.Equal(t, "route harvesting timed out", harvestErr.Message)

	// Ensure it actually timed out quickly (within reasonable bounds)
	assert.Less(t, elapsed, 200*time.Millisecond)
	assert.Greater(t, elapsed, 90*time.Millisecond)
}

func TestHarvestRoutes_Panic(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 1*time.Second)
	harvester.javaExtractRoutes = panicExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableJava)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.Error(t, err)
	assert.Nil(t, result)

	// Check that panic was caught and converted to HarvestError
	var harvestErr *HarvestError
	require.ErrorAs(t, err, &harvestErr)
	assert.Equal(t, "harvesting failed", harvestErr.Message)
}

func TestHarvestRoutes_SlowButSuccessful(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 200*time.Millisecond) // Enough time for slow operation
	harvester.javaExtractRoutes = slowButSuccessfulExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableJava)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []string{"/api/slow"}, result.Routes)
	assert.Equal(t, PartialRoutes, result.Kind)
}

func TestHarvestRoutes_EmptyResult(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 1*time.Second)
	harvester.javaExtractRoutes = emptyResultExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableJava)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Routes)
	assert.Equal(t, CompleteRoutes, result.Kind)
}

func TestHarvestRoutes_NonJavaLanguage(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 1*time.Second)
	// javaExtractRoutes should not be called for non-Java languages
	harvester.javaExtractRoutes = func(_ int32) (*RouteHarvesterResult, error) {
		t.Fatal("javaExtractRoutes should not be called for non-Java languages")
		return nil, nil
	}

	fileInfo := createTestFileInfo(svc.InstrumentableGolang)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.NoError(t, err)
	assert.Nil(t, result) // Should return nil for non-Java languages
}

func TestHarvestRoutes_MultipleTimeouts(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 50*time.Millisecond)
	harvester.javaExtractRoutes = timeoutExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableJava)

	// Test multiple calls to ensure timeout behavior is consistent
	for i := range 3 {
		result, err := harvester.HarvestRoutes(fileInfo)

		require.Error(t, err, "iteration %d should timeout", i)
		assert.Nil(t, result, "iteration %d should return nil result", i)

		var harvestErr *HarvestError
		require.ErrorAs(t, err, &harvestErr, "iteration %d should return HarvestError", i)
		assert.Equal(t, "route harvesting timed out", harvestErr.Message, "iteration %d should have timeout message", i)
	}
}

func TestHarvestNodejsRoutes_Successful(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 1*time.Second)
	harvester.nodeExtractRoutes = successfulExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableNodejs)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []string{"/api/users", "/api/orders"}, result.Routes)
	assert.Equal(t, CompleteRoutes, result.Kind)
}

func TestHarvestNodejsRoutes_Error(t *testing.T) {
	harvester := NewRouteHarvester(&services.RouteHarvestingConfig{}, []string{}, 1*time.Second)
	harvester.nodeExtractRoutes = errorExtractRoutes

	fileInfo := createTestFileInfo(svc.InstrumentableNodejs)

	result, err := harvester.HarvestRoutes(fileInfo)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to connect to Java process")
}

func TestFindScriptDirectory(t *testing.T) {
	// Create a temporary directory structure for testing
	tempDir := t.TempDir()

	isDirFunc = func(path string) bool {
		return !strings.HasSuffix(path, ".js")
	}

	// Create test directory structure:
	// tempDir/
	//   app/
	//     server.js
	//   src/
	//     index.js
	//   workdir/

	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "app"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "src"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "workdir"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "app", "server.js"), []byte(""), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "src", "index.js"), []byte(""), 0o644))

	tests := []struct {
		name     string
		root     string
		firstArg string
		cwd      string
		expected string
	}{
		{
			name:     "absolute path to directory",
			root:     tempDir,
			firstArg: "/app",
			cwd:      "/workdir",
			expected: filepath.Join(tempDir, "app") + "/",
		},
		{
			name:     "absolute path to file - extracts directory",
			root:     tempDir,
			firstArg: "/app/server.js",
			cwd:      "/workdir",
			expected: filepath.Join(tempDir, "app") + "/",
		},
		{
			name:     "absolute path to nested file",
			root:     tempDir,
			firstArg: "/src/index.js",
			cwd:      "/workdir",
			expected: filepath.Join(tempDir, "src") + "/",
		},
		{
			name:     "relative path falls back to cwd",
			root:     tempDir,
			firstArg: "server.js",
			cwd:      "/workdir",
			expected: filepath.Join(tempDir, "workdir") + "/",
		},
		{
			name:     "empty firstArg falls back to cwd",
			root:     tempDir,
			firstArg: "",
			cwd:      "/app",
			expected: filepath.Join(tempDir, "app") + "/",
		},
		{
			name:     "absolute path falls back to cwd",
			root:     tempDir,
			firstArg: "./something/path.js",
			cwd:      "/src",
			expected: filepath.Join(tempDir, "src") + "/",
		},
		{
			name:     "root path",
			root:     tempDir,
			firstArg: "/",
			cwd:      "/workdir",
			expected: filepath.Join(tempDir, "") + "/",
		},
		{
			name:     "path with multiple slashes",
			root:     tempDir,
			firstArg: "/app/nested/deep/file.js",
			cwd:      "/workdir",
			expected: filepath.Join(tempDir, "/app/nested/deep") + "/",
		},
		{
			name:     "cwd is root",
			root:     tempDir,
			firstArg: "index.js",
			cwd:      "/",
			expected: tempDir + "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindScriptDirectory(tt.root, tt.firstArg, tt.cwd)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindScriptDirectory_EdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	isDirFunc = func(path string) bool {
		return !strings.HasSuffix(path, ".js")
	}

	tests := []struct {
		name     string
		root     string
		firstArg string
		cwd      string
		expected string
	}{
		{
			name:     "empty root with absolute firstArg",
			root:     "",
			firstArg: "/app/server.js",
			cwd:      "/workdir",
			expected: "/app/",
		},
		{
			name:     "all parameters empty",
			root:     "",
			firstArg: "",
			cwd:      "",
			expected: "",
		},
		{
			name:     "firstArg with trailing slash",
			root:     tempDir,
			firstArg: "/app/",
			cwd:      "/workdir",
			expected: filepath.Join(tempDir, "/app") + "/",
		},
		{
			name:     "single slash in firstArg",
			root:     tempDir,
			firstArg: "/",
			cwd:      "/app",
			expected: filepath.Join(tempDir, "/") + "/",
		},
		{
			name:     "cwd with multiple levels",
			root:     tempDir,
			firstArg: "script.js",
			cwd:      "/some/deep/path",
			expected: filepath.Join(tempDir, "some/deep/path") + "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindScriptDirectory(tt.root, tt.firstArg, tt.cwd)
			assert.Equal(t, tt.expected, result)
		})
	}
}
