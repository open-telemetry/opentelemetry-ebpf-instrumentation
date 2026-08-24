// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadGemspecRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.gemspec")
	require.NoError(t, unix.Mkfifo(path, 0o600))

	assert.Empty(t, readGemspec(path))
}

func TestResolveServiceMetadataTreatsFIFOGemspecAsBoundary(t *testing.T) {
	root := t.TempDir()
	writeRubyFile(t, filepath.Join(root, "outer.gemspec"), []byte(`
Gem::Specification.new("outer", "9.9.9") do |spec|
end
`))
	require.NoError(t, unix.Mkdir(filepath.Join(root, "app"), 0o755))
	require.NoError(t, unix.Mkfifo(filepath.Join(root, "app", "orders.gemspec"), 0o600))
	fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

	require.NoError(t, ResolveServiceMetadata(fileInfo))

	service := fileInfo.ServiceAttrs()
	assert.Equal(t, "app", service.UID.Name)
	assert.Empty(t, service.Metadata[serviceVersion])
}
