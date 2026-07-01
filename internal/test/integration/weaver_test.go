// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// upstreamSemconvSchemaURLPrefix uniquely identifies the upstream OpenTelemetry
// semantic conventions registry among `schemas/obi/manifest.yaml` dependencies.
const upstreamSemconvSchemaURLPrefix = "https://opentelemetry.io/schemas/"

func TestExtendsNamespaceAdviceIsActionable(t *testing.T) {
	const message = "Attribute 'http.custom' extends an existing namespace"

	report := weaverReport{
		Samples: []json.RawMessage{json.RawMessage(`{
			"span": {
				"live_check_result": {
					"all_advice": [{
						"id": "extends_namespace",
						"message": "Attribute 'http.custom' extends an existing namespace",
						"level": "information",
						"signal_type": "span",
						"signal_name": "GET /test"
					}]
				}
			}
		}`)},
		Statistics: weaverStatistics{
			AdviceMessageCounts: map[string]int{message: 1},
		},
	}

	adviceByMsg := collectAdviceInfo(report.Samples)
	require.Equal(t, 1, countActionableAdvisories(&report.Statistics, adviceByMsg))
}

// TestSemconvVersionMatchesManifest guards against drift between the Go-side
// semconv import and the upstream-semconv dependency pinned in the OBI
// schema registry's manifest. The two MUST move together — bumping the Go
// import without updating `schemas/obi/manifest.yaml` (or vice versa) would
// cause weaver to validate emissions against the wrong version of the
// upstream registry.
func TestSemconvVersionMatchesManifest(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", "schemas", "obi", "manifest.yaml")
	raw, err := os.ReadFile(manifestPath)
	require.NoError(t, err, "failed to read %s", manifestPath)

	var manifest struct {
		Dependencies []struct {
			SchemaURL    string `yaml:"schema_url"`
			RegistryPath string `yaml:"registry_path"`
		} `yaml:"dependencies"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &manifest), "failed to parse manifest YAML")
	require.NotEmpty(t, manifest.Dependencies, "manifest has no dependencies entry")

	// Locate the upstream semconv dependency by schema_url prefix rather than
	// assuming a position in the list — keeps the test robust if other
	// registries get added as dependencies later.
	depIdx := -1
	for i, d := range manifest.Dependencies {
		if strings.HasPrefix(d.SchemaURL, upstreamSemconvSchemaURLPrefix) {
			depIdx = i
			break
		}
	}
	require.NotEqual(t, -1, depIdx,
		"manifest dependencies do not contain an upstream semconv entry "+
			"(no schema_url with prefix %q)", upstreamSemconvSchemaURLPrefix)
	dep := manifest.Dependencies[depIdx]

	// The schema_url ends with `/<version>`; extract that segment.
	manifestSemconvVersion := dep.SchemaURL[strings.LastIndex(dep.SchemaURL, "/")+1:]

	require.Equal(t, SemconvVersion(), manifestSemconvVersion,
		"go.opentelemetry.io/otel/semconv version (%s) does not match "+
			"the upstream semconv schema_url version pinned in "+
			"schemas/obi/manifest.yaml (%s); bump them together",
		SemconvVersion(), manifestSemconvVersion)

	// The registry_path also embeds the version; sanity-check it matches.
	// We accept either the upstream git-URL form (`@vX.Y.Z`) or the local
	// pre-fetched cache form (`upstream-vX.Y.Z`) — `make fetch-upstream-semconv`
	// populates the latter and the manifest references it so weaver doesn't
	// need network on every container start.
	gitRefspec := "@v" + manifestSemconvVersion
	localRefspec := "upstream-v" + manifestSemconvVersion
	if !strings.Contains(dep.RegistryPath, gitRefspec) &&
		!strings.Contains(dep.RegistryPath, localRefspec) {
		t.Fatalf("manifest semconv dependency registry_path (%s) does not pin "+
			"%s (git form) or %s (local cache form)",
			dep.RegistryPath, gitRefspec, localRefspec)
	}
}
