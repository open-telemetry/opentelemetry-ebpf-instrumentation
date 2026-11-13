// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// The slim images are stripped; the full images keep a symbol table.
func TestSuite_PythonExceptions(t *testing.T) {
	for _, image := range []string{
		"python:3.9.25-slim-bookworm",
		"python:3.10.20-slim-bookworm",
		"python:3.11.15-slim-bookworm",
		"python:3.12.13-slim-bookworm",
		"python:3.13.14-slim-bookworm",
		"python:3.14.7-slim-bookworm",
		"python:3.13.14-bookworm",
		"python:3.14.7-bookworm",
	} {
		t.Run(image, func(t *testing.T) {
			asyncSkipReason := ""
			if strings.Contains(image, "-slim-") {
				asyncSkipReason = "async request ownership on stripped Python builds is deferred"
			}
			runPythonExceptionsSuite(t, image, "PYTHON_EXCEPTION_IMAGE="+image,
				"PYTHON_EXCEPTION_ASYNC_SKIP_REASON="+asyncSkipReason)
		})
	}
}

// Source-built runtimes: a static interpreter, an LTO build, and a
// free-threaded build that capture must refuse.
func TestSuite_PythonExceptions_Builds(t *testing.T) {
	for _, build := range []string{"static", "lto", "free-threaded"} {
		t.Run(build, func(t *testing.T) {
			asyncSkipReason := ""
			if build == "lto" {
				asyncSkipReason = "async exception capture on LTO Python builds is deferred"
			}
			runPythonExceptionsSuite(t, build,
				"PYTHON_EXCEPTION_ASYNC_SKIP_REASON="+asyncSkipReason,
				"PYTHON_EXCEPTION_IMAGE=python:3.14.7-slim-bookworm",
				"PYTHON_EXCEPTION_VERSION=3.14.7",
				"PYTHON_EXCEPTION_BUILD="+build)
		})
	}
}

func runPythonExceptionsSuite(t *testing.T, name string, env ...string) {
	tag := strings.ReplaceAll(name, ":", "-")
	compose, err := docker.ComposeSuite("docker-compose-python-exceptions.yml",
		path.Join(pathOutput, "test-suite-python-exceptions-"+tag+".log"))
	require.NoError(t, err)
	// Its own project, so other suites' teardown cannot remove it.
	compose.Env = append(compose.Env, "COMPOSE_PROJECT_NAME=pyexc", "PYTHON_EXCEPTION_TAG="+tag)
	compose.Env = append(compose.Env, env...)
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Run("obi"))
}
