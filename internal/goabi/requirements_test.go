// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/goversion"
)

func TestRequirementsByGoVersion(t *testing.T) {
	legacy, err := Requirements(goversion.MustParse("go1.26.9"))
	require.NoError(t, err)
	require.Len(t, legacy, 6)
	for _, definition := range legacy {
		assert.Equal(t, "runtime.moduledata", definition.OutputType)
	}
	rc, err := Requirements(goversion.MustParse("go1.27rc1"))
	require.NoError(t, err)
	assert.Equal(t, legacy, rc)

	current, err := Requirements(goversion.MustParse("1.27.0"))
	require.NoError(t, err)
	assert.Greater(t, len(current), len(legacy))
	prefixed, err := Requirements(goversion.MustParse("go1.27.0"))
	require.NoError(t, err)
	assert.Equal(t, current, prefixed)
	patch, err := Requirements(goversion.MustParse("go1.27.1"))
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

func TestRequirementsRejectsUnsupportedGoVersions(t *testing.T) {
	_, err := Requirements(goversion.MustParse("go1.16.15"))
	require.ErrorContains(t, err, "unsupported Go version")
}
