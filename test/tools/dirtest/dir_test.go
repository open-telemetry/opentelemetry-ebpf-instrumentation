// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/test/tools"
)

// Unorthodox way to provide another test case to ../dir.go: we are testing
// that the relative path still works when invoked from another directory depth
func TestProjectDir(t *testing.T) {
	prjDir := tools.ProjectDir()
	// Test that the project relative dir is correct by checking for the
	// existence of a file that should be only placed in the project
	// root (e.g. Makefile)
	fi, err := os.Stat(path.Join(prjDir, "Makefile"))
	require.NoError(t, err)
	require.NotNil(t, fi)
	assert.NotEmpty(t, fi.Name())
}
