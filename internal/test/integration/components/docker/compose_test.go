// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const composeFixture = `
services:
  obi:
    build:
      context: ../../..
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
    image: hatest-obi
  obi-b:
    build:
      context: ../../..
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
    image: hatest-obi-b
  testserver:
    build:
      context: ../../..
      dockerfile: ./internal/test/integration/components/testserver/Dockerfile
    image: hatest-testserver
  prepulled:
    image: postgres:16
  stringbuild:
    build: ../../..
    image: hatest-stringbuild
`

func fixtureCompose(t *testing.T) *Compose {
	t.Helper()

	path := filepath.Join(t.TempDir(), "compose.yml")
	require.NoError(t, os.WriteFile(path, []byte(composeFixture), 0o600))

	return &Compose{Path: path}
}

func TestServicesToBuildDisabledWithoutEnv(t *testing.T) {
	c := fixtureCompose(t)

	_, ok := c.servicesToBuild()
	assert.False(t, ok, "must fall back to building everything")
}

func TestServicesToBuildSkipsPrebuiltImages(t *testing.T) {
	t.Setenv("PREBUILT_IMAGES", "hatest-obi, hatest-obi-b")
	c := fixtureCompose(t)

	services, ok := c.servicesToBuild()
	require.True(t, ok)
	assert.Equal(t, []string{"stringbuild", "testserver"}, services,
		"services without a build section or with a prebuilt image must be skipped")
}

func TestServicesToBuildFallsBackOnUnreadableFile(t *testing.T) {
	t.Setenv("PREBUILT_IMAGES", "hatest-obi")
	c := &Compose{Path: filepath.Join(t.TempDir(), "missing.yml")}

	_, ok := c.servicesToBuild()
	assert.False(t, ok, "unparseable compose file must fall back to building everything")
}

func TestComposeArgsIncludeOverrides(t *testing.T) {
	c := &Compose{
		Path:          "compose.yml",
		OverridePaths: []string{"first.yml", "second.yml"},
	}

	assert.Equal(t, []string{
		"compose", "--ansi", "never",
		"-f", "compose.yml",
		"-f", "first.yml",
		"-f", "second.yml",
		"up", "--detach",
	}, c.composeArgs("up", "--detach"))
}
