// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const generatedCompose = `
name: oats
services:
  autoinstrumenter:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
  absolute:
    build:
      context: /src
      dockerfile: /src/internal/test/integration/components/obi/Dockerfile
  javaagent:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile-with-javaagent
    image: hatest-obi-javaagent
  withargs:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
      args:
        FOO: bar
  withtarget:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
      target: builder
  testserver:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/testserver/Dockerfile
  lgtm:
    image: grafana/otel-lgtm:latest
`

func TestSplitServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte(generatedCompose), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &compose{path: path, files: []string{path}}

	obiServices, toBuild, err := c.splitServices()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"absolute", "autoinstrumenter"}; !slices.Equal(obiServices, want) {
		t.Errorf("obi services = %v, want %v", obiServices, want)
	}
	if want := []string{"javaagent", "testserver", "withargs", "withtarget"}; !slices.Equal(toBuild, want) {
		t.Errorf("services to build = %v, want %v", toBuild, want)
	}
}

func TestSplitServicesRejectsShortFormBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	shortForm := "services:\n  autoinstrumenter:\n    build: ./internal/test/integration/components/obi\n"
	if err := os.WriteFile(path, []byte(shortForm), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &compose{path: path, files: []string{path}}

	if _, _, err := c.splitServices(); err == nil {
		t.Error("expected an error so up() falls back to building every service")
	}
}

func TestUsePrebuiltOBI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	c := &compose{path: path, files: []string{path}}

	if err := c.usePrebuiltOBI([]string{"autoinstrumenter"}); err != nil {
		t.Fatal(err)
	}
	if len(c.files) != 2 {
		t.Fatalf("files = %v, want the generated file plus the override", c.files)
	}
	data, err := os.ReadFile(c.files[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "autoinstrumenter:\n        image: hatest-obi") {
		t.Errorf("override = %q", data)
	}
}
