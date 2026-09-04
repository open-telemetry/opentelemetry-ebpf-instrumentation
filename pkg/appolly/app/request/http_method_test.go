// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsKnownHTTPMethod(t *testing.T) {
	for _, m := range []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY", "TRACE"} {
		assert.True(t, IsKnownHTTPMethod(m), m)
	}

	for _, m := range []string{"", "get", "PURGE", "PROPFIND", "GET ", "\x16\x03\x01"} {
		assert.False(t, IsKnownHTTPMethod(m), m)
	}
}

func TestParseKnownHTTPMethods(t *testing.T) {
	t.Run("unset falls back to the semconv defaults", func(t *testing.T) {
		for _, env := range []string{"", "   ", ",", " , , "} {
			got := parseKnownHTTPMethods(env)
			assert.Len(t, got, len(defaultKnownHTTPMethods), "env %q", env)
			assert.Contains(t, got, "GET", "env %q", env)
		}
	})

	t.Run("override replaces the defaults", func(t *testing.T) {
		got := parseKnownHTTPMethods("PROPFIND, REPORT ,MKCOL")
		assert.Len(t, got, 3)
		for _, m := range []string{"PROPFIND", "REPORT", "MKCOL"} {
			assert.Contains(t, got, m)
		}
		assert.NotContains(t, got, "GET", "an override replaces the enum rather than extending it")
	})
}

// The spec mandates this exact name, so a typo would silently leave the
// override undiscoverable while every other test still passed.
func TestKnownMethodsEnvVarName(t *testing.T) {
	assert.Equal(t, "OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS", envKnownMethods)
}

// The override resolves once per process, so exercising it end to end needs a
// fresh one: parseKnownHTTPMethods being correct does not prove it is wired in.
func TestKnownHTTPMethodsOverrideIsWired(t *testing.T) {
	const childEnv = "OBI_TEST_KNOWN_METHODS_CHILD"

	if os.Getenv(childEnv) == "1" {
		assert.True(t, IsKnownHTTPMethod("PROPFIND"), "the override must be honored")
		assert.False(t, IsKnownHTTPMethod("GET"), "an override replaces the enum")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestKnownHTTPMethodsOverrideIsWired$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", envKnownMethods+"=PROPFIND")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child run failed:\n%s", out)
}
