// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var springControllerRoutes = []string{
	"/api",
	"/v1",
	"/api/assets/*",
	"/api/orders",
	"/v1/assets/*",
	"/v1/orders",
	"/api/orders/{orderId}",
	"/api/users/{id}",
	"/v1/orders/{orderId}",
	"/v1/users/{id}",
}

func TestScanArchiveClassEntry(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  bool
	}{
		{
			name:  "root class",
			entry: "com/example/SpringController.class",
			want:  true,
		},
		{
			name:  "spring boot application class",
			entry: "BOOT-INF/classes/com/example/SpringController.class",
			want:  true,
		},
		{
			name:  "war application class",
			entry: "WEB-INF/classes/com/example/SpringController.class",
			want:  true,
		},
		{
			name:  "spring boot dependency class",
			entry: "BOOT-INF/lib/com/example/SpringController.class",
			want:  false,
		},
		{
			name:  "war dependency class",
			entry: "WEB-INF/lib/com/example/SpringController.class",
			want:  false,
		},
		{
			name:  "metadata class",
			entry: "META-INF/versions/21/com/example/SpringController.class",
			want:  false,
		},
		{
			name:  "not a class",
			entry: "com/example/SpringController.txt",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, scanArchiveClassEntry(tt.entry))
		})
	}
}

func TestScanDir(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "com", "example"), 0o755))
	writeClassFixture(t, filepath.Join(root, "com", "example", "SpringController.class"), "com/example/SpringController.class")
	writeClassFixture(t, filepath.Join(root, "com", "example", "ignored.txt"), "com/example/JaxController.class")

	extractor := NewExtractor()
	require.NoError(t, extractor.scanDir(context.Background(), root))

	assert.ElementsMatch(t, springControllerRoutes, mapKeys(extractor.routes))
	assert.Equal(t, 1, extractor.classesScanned)
}

func TestScanDirSkipsOversizedClassFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "Large.class"), make([]byte, MaxJavaClassScanBytes+1), 0o644))

	extractor := NewExtractor()
	require.NoError(t, extractor.scanDir(context.Background(), root))

	assert.Empty(t, extractor.routes)
	assert.Zero(t, extractor.classesScanned)
}

func TestScanDirReturnsContextErrorWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	extractor := NewExtractor()
	err := extractor.scanDir(ctx, t.TempDir())

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, extractor.routes)
	assert.Zero(t, extractor.classesScanned)
}

func TestScanArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.jar")
	writeZip(t, path, []zipEntry{
		{name: "BOOT-INF/classes/com/example/SpringController.class", data: classFixture(t, "com/example/SpringController.class")},
		{name: "BOOT-INF/lib/com/example/JaxController.class", data: classFixture(t, "com/example/JaxController.class")},
		{name: "META-INF/versions/21/com/example/MicronautController.class", data: classFixture(t, "com/example/MicronautController.class")},
		{name: "BOOT-INF/classes/com/example/ignored.txt", data: classFixture(t, "com/example/QuarkusReactiveController.class")},
	})

	extractor := NewExtractor()
	require.NoError(t, extractor.scanArchive(context.Background(), path))

	assert.ElementsMatch(t, springControllerRoutes, mapKeys(extractor.routes))
	assert.Equal(t, 1, extractor.classesScanned)
}

func TestScanArchiveSkipsOversizedClassEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.jar")
	writeZip(t, path, []zipEntry{
		{name: "com/example/Large.class", data: make([]byte, MaxJavaClassScanBytes+1)},
	})

	extractor := NewExtractor()
	require.NoError(t, extractor.scanArchive(context.Background(), path))

	assert.Empty(t, extractor.routes)
	assert.Zero(t, extractor.classesScanned)
}

func TestScanArchiveReturnsContextErrorWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	path := filepath.Join(t.TempDir(), "app.jar")
	writeZip(t, path, []zipEntry{
		{name: "com/example/SpringController.class", data: classFixture(t, "com/example/SpringController.class")},
	})

	extractor := NewExtractor()
	err := extractor.scanArchive(ctx, path)

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, extractor.routes)
	assert.Zero(t, extractor.classesScanned)
}

type zipEntry struct {
	name string
	data []byte
}

func writeZip(t *testing.T, path string, entries []zipEntry) {
	t.Helper()

	file, err := os.Create(path)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, file.Close())
	}()

	writer := zip.NewWriter(file)
	defer func() {
		require.NoError(t, writer.Close())
	}()

	for _, entry := range entries {
		w, err := writer.Create(entry.name)
		require.NoError(t, err)
		_, err = w.Write(entry.data)
		require.NoError(t, err)
	}
}

func writeClassFixture(t *testing.T, path, fixture string) {
	t.Helper()

	require.NoError(t, os.WriteFile(path, classFixture(t, fixture), 0o644))
}

func classFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("test_files", "classes", filepath.FromSlash(name)))
	require.NoError(t, err)
	return data
}
