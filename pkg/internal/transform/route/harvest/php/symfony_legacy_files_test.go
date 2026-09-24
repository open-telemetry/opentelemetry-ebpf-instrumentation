// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLegacySymfonyYAMLEntries(t *testing.T) {
	root := t.TempDir()
	yamlPath := writeSymfonyTestFile(t, root, "app/config/routing.yaml", "routes: {}")
	ymlPath := writeSymfonyTestFile(t, root, "app/config/routing.yml", "routes: {}")

	assert.Equal(t, []string{yamlPath, ymlPath}, legacySymfonyYAMLEntries(root))
	assert.Nil(t, legacySymfonyYAMLEntries(t.TempDir()))
}

func TestLegacySymfonyXMLEntries(t *testing.T) {
	root := t.TempDir()
	entry := writeSymfonyTestFile(t, root, "app/config/routing.xml", "<routes/>")
	alpha := writeSymfonyTestFile(t, root, "app/config/routing/alpha.XML", "<routes/>")
	beta := writeSymfonyTestFile(t, root, "app/config/routing/beta.xml", "<routes/>")
	writeSymfonyTestFile(t, root, "app/config/routing/ignored.yaml", "routes: {}")

	assert.Equal(t, []string{entry, alpha, beta}, legacySymfonyXMLEntries(root))
	assert.Nil(t, legacySymfonyXMLEntries(t.TempDir()))
}
