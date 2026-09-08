// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
	"archive/zip"
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJavaProperty(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		expected string
	}{
		{
			name:     "property among other properties",
			contents: "#Thu Nov 27 10:00:00 UTC 2025\njava.version=21.0.5\notel.obi.java.agent.version=3\nuser.dir=/app\n",
			expected: "3",
		},
		{
			name:     "last line without a line break",
			contents: "java.version=21.0.5\notel.obi.java.agent.version=3",
			expected: "3",
		},
		{
			name:     "carriage return line endings",
			contents: "java.version=21.0.5\r\notel.obi.java.agent.version=3\r\n",
			expected: "3",
		},
		{
			name:     "indented property",
			contents: "  otel.obi.java.agent.version=3\n",
			expected: "3",
		},
		{
			name:     "absent property",
			contents: "java.version=21.0.5\nuser.dir=/app\n",
			expected: "",
		},
		{
			name:     "property name is only a prefix of another one",
			contents: "otel.obi.java.agent.version.extra=3\n",
			expected: "",
		},
		{
			name:     "empty stream",
			contents: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := javaProperty(strings.NewReader(tt.contents), agentVersionProperty)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, value)
		})
	}
}

func TestAgentVersionFromJar(t *testing.T) {
	t.Run("version marker in the agent jar", func(t *testing.T) {
		version, err := agentVersionFromJar(agentJar(t, agentVersionResource, "#a comment\n"+agentVersionProperty+"=3\n"))
		require.NoError(t, err)
		assert.Equal(t, "3", version)
	})

	t.Run("agent jar without a version marker", func(t *testing.T) {
		_, err := agentVersionFromJar(agentJar(t, "unrelated.properties", "some.key=3\n"))
		require.ErrorIs(t, err, errNoAgentVersion)
	})

	t.Run("version marker without the version property", func(t *testing.T) {
		_, err := agentVersionFromJar(agentJar(t, agentVersionResource, "some.key=3\n"))
		require.ErrorIs(t, err, errNoAgentVersion)
	})

	t.Run("agent jar that is not a jar", func(t *testing.T) {
		_, err := agentVersionFromJar([]byte("not a jar"))
		require.Error(t, err)
		require.NotErrorIs(t, err, errNoAgentVersion)
	})
}

func TestJavaInjector_VerifyAgentVersion(t *testing.T) {
	injector := &JavaInjector{log: slog.Default(), agentVersion: "3"}

	require.NoError(t, injector.verifyAgentVersion(1000, "3"))

	err := injector.verifyAgentVersion(1000, "2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version 2, expected 3")

	err = injector.verifyAgentVersion(1000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version unknown, expected 3")
}

func agentJar(t *testing.T, name, contents string) []byte {
	t.Helper()

	buf := bytes.Buffer{}
	archive := zip.NewWriter(&buf)

	entry, err := archive.Create(name)
	require.NoError(t, err)
	_, err = entry.Write([]byte(contents))
	require.NoError(t, err)
	require.NoError(t, archive.Close())

	return buf.Bytes()
}
