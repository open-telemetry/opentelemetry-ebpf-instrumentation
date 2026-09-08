// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirementsByGoVersion(t *testing.T) {
	legacy, err := Requirements("go1.26.9")
	require.NoError(t, err)
	require.Len(t, legacy, 6)
	for _, definition := range legacy {
		assert.Equal(t, "runtime.moduledata", definition.OutputType)
	}
	rc, err := Requirements("go1.27rc1")
	require.NoError(t, err)
	assert.Equal(t, legacy, rc)

	current, err := Requirements("1.27.0")
	require.NoError(t, err)
	assert.Greater(t, len(current), len(legacy))
	prefixed, err := Requirements("go1.27.0")
	require.NoError(t, err)
	assert.Equal(t, current, prefixed)
	patch, err := Requirements("go1.27.1")
	require.NoError(t, err)
	assert.Equal(t, current, patch)

	keys := map[string]struct{}{}
	for _, definition := range current {
		_, duplicate := keys[definition.Key()]
		assert.False(t, duplicate, definition.Key())
		keys[definition.Key()] = struct{}{}
	}
	assert.Contains(t, keys, "internal/abi.ITab.Inter")
}

func TestDefinitionsCanAssignResolvedFacts(t *testing.T) {
	for _, definition := range requirementDefinitions {
		assert.NotNil(t, definition.query, definition.Key())
		assert.NotNil(t, definition.assign, definition.Key())
	}
}

func TestRequirementsRejectsInvalidGoVersions(t *testing.T) {
	for _, goVersion := range []string{
		"release go1.27.0",
		"go1.27.0 release",
		"devel go1.29-abcdef",
	} {
		t.Run(goVersion, func(t *testing.T) {
			_, err := Requirements(goVersion)
			require.ErrorContains(t, err, "invalid Go version")
		})
	}
}
