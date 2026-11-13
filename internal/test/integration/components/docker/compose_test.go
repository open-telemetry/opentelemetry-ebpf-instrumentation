// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"os"
	"path/filepath"
	"strings"
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

	return composeFromYAML(t, composeFixture)
}

func composeFromYAML(t *testing.T, content string) *Compose {
	t.Helper()

	path := filepath.Join(t.TempDir(), "compose.yml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

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

func TestServicesToBuildResolvesImageVariables(t *testing.T) {
	t.Setenv("PREBUILT_IMAGES", "hatest-obi")
	c := composeFromYAML(t, `
services:
  defaulted:
    build: ../../..
    image: ${DEFAULTED_OBI_IMAGE:-hatest-obi}
  overridden:
    build: ../../..
    image: ${OVERRIDDEN_OBI_IMAGE:-hatest-obi}
`)
	c.Env = []string{"OVERRIDDEN_OBI_IMAGE=hatest-other"}

	services, ok := c.servicesToBuild()
	require.True(t, ok)
	assert.Equal(t, []string{"overridden"}, services,
		"an image variable must be compared after compose resolves it")
}

func TestServicesToBuildSkipsInactiveProfiles(t *testing.T) {
	t.Setenv("PREBUILT_IMAGES", "hatest-obi")
	c := composeFromYAML(t, `
services:
  always:
    build: ../../..
  central:
    build: ../../..
    profiles: [central]
`)

	services, ok := c.servicesToBuild()
	require.True(t, ok)
	assert.Equal(t, []string{"always"}, services, "services of inactive profiles are never started")

	c.Env = []string{"COMPOSE_PROFILES=tools,central"}
	services, ok = c.servicesToBuild()
	require.True(t, ok)
	assert.Equal(t, []string{"always", "central"}, services)
}

func TestServicesToBuildFallsBackOnUnreadableFile(t *testing.T) {
	t.Setenv("PREBUILT_IMAGES", "hatest-obi")
	c := &Compose{Path: filepath.Join(t.TempDir(), "missing.yml")}

	_, ok := c.servicesToBuild()
	assert.False(t, ok, "unparseable compose file must fall back to building everything")
}

func TestObiServices(t *testing.T) {
	c := composeFromYAML(t, `
services:
  obi:
    image: hatest-obi
  client-obi:
    image: hatest-obi
  obi-config-migrate:
    image: hatest-obi
  testserver:
    image: hatest-testserver
  mobile-app:
    image: hatest-mobile
`)

	services, ok := c.obiServices()
	require.True(t, ok)
	assert.Equal(t, []string{"client-obi", "obi", "obi-config-migrate"}, services)
}

func TestObiServicesFallsBackOnUnreadableFile(t *testing.T) {
	c := &Compose{Path: filepath.Join(t.TempDir(), "missing.yml")}

	_, ok := c.obiServices()
	assert.False(t, ok, "an unparseable compose file must fall back to stopping everything gracefully")
}

func TestBuildsNameWhatServicesBuild(t *testing.T) {
	dir := t.TempDir()
	composeAt := func(file, content string) *Compose {
		path := filepath.Join(dir, file)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return &Compose{Path: path}
	}
	first := composeAt("first.yml", `
services:
  tagged:
    build:
      context: ../../..
      dockerfile: testserver/Dockerfile
    image: ${TAGGED_IMAGE:-hatest-tagged}
  untagged:
    build: ../../..
  envarg:
    build:
      context: ../../..
      args:
        - BASE_IMAGE
    image: hatest-envarg
`)
	same := composeAt("same.yml", `
services:
  other:
    build:
      context: ../../..
      dockerfile: testserver/Dockerfile
    image: hatest-tagged
`)
	different := composeAt("different.yml", `
services:
  other:
    build:
      context: ../../..
      dockerfile: dotnetserver/Dockerfile
    image: hatest-tagged
`)

	builds := first.builds([]string{"tagged", "untagged", "envarg"})
	require.Len(t, builds, 3)
	assert.True(t, strings.HasPrefix(builds[0], "hatest-tagged@"))
	assert.True(t, strings.HasPrefix(builds[1], "first.yml/untagged@"))
	assert.Equal(t, builds[0], same.builds([]string{"other"})[0], "the same definition is the same build")
	assert.NotEqual(t, builds[0], different.builds([]string{"other"})[0], "a tag reused for another Dockerfile is another build")

	first.Env = []string{"BASE_IMAGE=debian"}
	assert.NotEqual(t, builds[2], first.builds([]string{"envarg"})[0], "args taken from the environment are part of the build")
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

func TestComposeSuiteWithConfigMigration(t *testing.T) {
	compose, err := ComposeSuiteWithConfigMigration(
		"compose.yml",
		filepath.Join(t.TempDir(), "compose.log"),
		ConfigMigration{
			Source: "obi-config.yml",
			Output: "obi-config-v2.yml",
			Image:  "hatest-obi",
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, compose.Logger.Close())
	})

	require.Len(t, compose.OverridePaths, 1)
	assert.Equal(t, configMigrationOverride, filepath.Base(compose.OverridePaths[0]))
	assert.Contains(t, compose.Env, "OBI_CONFIG_MIGRATION_SOURCE=obi-config.yml")
	assert.Contains(t, compose.Env, "OBI_CONFIG_MIGRATION_OUTPUT=obi-config-v2.yml")
	assert.Contains(t, compose.Env, "OBI_CONFIG_MIGRATION_IMAGE=hatest-obi")
}
