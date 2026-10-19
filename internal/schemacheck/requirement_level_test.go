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

// carrierFiles returns every registry file. A signal or attribute group is a
// carrier where it references an attribute with `ref`, which is what owes a
// level; the attribute's own definition, under `attributes:`, declares none, and
// upstream semconv declares no level on its definitions either.
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
	Ref              string    `yaml:"ref"`
	RefGroup         string    `yaml:"ref_group"`
	RequirementLevel yaml.Node `yaml:"requirement_level"`
}

type registryAttributeGroup struct {
	ID         string           `yaml:"id"`
	Visibility string           `yaml:"visibility"`
	Attributes []carrierAttrRef `yaml:"attributes"`
}

type registrySpan struct {
	Type       string           `yaml:"type"`
	Kind       string           `yaml:"kind"`
	Attributes []carrierAttrRef `yaml:"attributes"`
}

type registryMetric struct {
	Name       string           `yaml:"name"`
	Attributes []carrierAttrRef `yaml:"attributes"`
}

// registryFile is the part of a definition/2 file the carrier checks read.
type registryFile struct {
	Attributes []struct {
		Key string `yaml:"key"`
	} `yaml:"attributes"`
	AttributeGroups []registryAttributeGroup `yaml:"attribute_groups"`
	Spans           []registrySpan           `yaml:"spans"`
	Metrics         []registryMetric         `yaml:"metrics"`
}

func registryFiles(t *testing.T) map[string]registryFile {
	t.Helper()

	out := map[string]registryFile{}
	for _, path := range carrierFiles(t) {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f registryFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)
		out[path] = f
	}
	return out
}

// definedAttributes returns the keys this registry defines itself.
func definedAttributes(files map[string]registryFile) map[string]struct{} {
	out := map[string]struct{}{}
	for _, f := range files {
		for _, a := range f.Attributes {
			out[a.Key] = struct{}{}
		}
	}
	return out
}

type carrierAttr struct {
	file  string
	group string
	name  string
	level yaml.Node
}

func carrierAttributes(t *testing.T) []carrierAttr {
	t.Helper()

	files := registryFiles(t)
	defined := definedAttributes(files)

	var out []carrierAttr
	for path, f := range files {
		file := filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
		add := func(group string, refs []carrierAttrRef, skip func(string) bool) {
			for _, a := range refs {
				if a.Ref == "" || (skip != nil && skip(a.Ref)) {
					continue
				}
				out = append(out, carrierAttr{file: file, group: group, name: a.Ref, level: a.RequirementLevel})
			}
		}
		for _, s := range f.Spans {
			add(s.Type, s.Attributes, nil)
		}
		for _, m := range f.Metrics {
			add(m.Name, m.Attributes, nil)
		}
		for _, g := range f.AttributeGroups {
			// A public group that lists an attribute this registry defines is
			// that definition's documentation, not a carrier: a level there
			// would be as meaningless as on the definition itself.
			documents := func(key string) bool {
				_, ok := defined[key]
				return g.Visibility == "public" && ok
			}
			add(g.ID, g.Attributes, documents)
		}
	}
	return out
}

// Every attribute a span or metric carries states when it is present.
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
