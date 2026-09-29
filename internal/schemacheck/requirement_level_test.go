// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// carrierFiles returns every registry file. A group is a carrier where it
// references an attribute with `ref`, which is what owes a level; where it
// declares one with `id` it is a definition, and upstream semconv declares no
// level on its definitions either. The distinction is per attribute, not per
// file: registry.obi.exception references upstream's exception.message.
func carrierFiles(t *testing.T) []string {
	t.Helper()

	// Every YAML under the registry, at any depth: scoping this to known
	// filenames or a fixed depth would silently drop a carrier declared in a
	// new one.
	var out []string
	require.NoError(t, filepath.WalkDir(obiGroupsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".yaml" {
			out = append(out, path)
		}
		return nil
	}))
	return out
}

type carrierAttrRef struct {
	ID               string    `yaml:"id"`
	Ref              string    `yaml:"ref"`
	RequirementLevel yaml.Node `yaml:"requirement_level"`
}

type carrierGroup struct {
	ID         string           `yaml:"id"`
	Type       string           `yaml:"type"`
	Extends    string           `yaml:"extends"`
	Attributes []carrierAttrRef `yaml:"attributes"`
}

type carrierGroupsFile struct {
	Groups []carrierGroup `yaml:"groups"`
}

type carrierAttr struct {
	file  string
	group string
	name  string
	level yaml.Node
}

func carrierAttributes(t *testing.T) []carrierAttr {
	t.Helper()

	var out []carrierAttr
	for _, path := range carrierFiles(t) {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f carrierGroupsFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)

		for _, g := range f.Groups {
			for _, a := range g.Attributes {
				// A group that references an attribute is a carrier and owes a
				// level. One that declares it with `id` is a definition, where
				// a level would be meaningless — upstream declares none either.
				if a.Ref == "" {
					continue
				}
				name := a.Ref
				out = append(out, carrierAttr{
					file:  filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path),
					group: g.ID,
					name:  name,
					level: a.RequirementLevel,
				})
			}
		}
	}
	return out
}

// Every attribute a span or metric group carries states when it is present.
// Without this the registry names an attribute but leaves a consumer unable to
// tell one that is always there from one that appears on a single subtype.
func TestEveryCarrierAttributeDeclaresARequirementLevel(t *testing.T) {
	attrs := carrierAttributes(t)
	require.NotEmpty(t, attrs, "no carrier attributes found under %s", obiGroupsDir)

	for _, a := range attrs {
		assert.Falsef(t, a.level.IsZero(),
			"%s: %s declares no requirement_level for %s", a.file, a.group, a.name)
	}
}

// A level is either one of the plain vocabulary words or a single-key mapping
// naming the condition. weaver rejects an unknown word, but it accepts a
// conditionally_required with an empty condition, which tells a reader nothing.
func TestRequirementLevelsAreWellFormed(t *testing.T) {
	plain := map[string]struct{}{
		"required":    {},
		"recommended": {},
		"opt_in":      {},
	}

	for _, a := range carrierAttributes(t) {
		if a.level.IsZero() {
			continue
		}

		if a.level.Kind == yaml.ScalarNode {
			_, ok := plain[a.level.Value]
			assert.Truef(t, ok, "%s: %s/%s has unknown requirement_level %q",
				a.file, a.group, a.name, a.level.Value)
			continue
		}

		var mapping map[string]string
		require.NoErrorf(t, a.level.Decode(&mapping),
			"%s: %s/%s requirement_level is neither a word nor a condition mapping",
			a.file, a.group, a.name)

		assert.Lenf(t, mapping, 1, "%s: %s/%s requirement_level names %d conditions, expected one",
			a.file, a.group, a.name, len(mapping))

		for kind, condition := range mapping {
			assert.Containsf(t, []string{"conditionally_required", "recommended"}, kind,
				"%s: %s/%s has unknown conditional requirement_level %q", a.file, a.group, a.name, kind)
			assert.NotEmptyf(t, strings.TrimSpace(condition),
				"%s: %s/%s declares %s with no condition", a.file, a.group, a.name, kind)
		}
	}
}
