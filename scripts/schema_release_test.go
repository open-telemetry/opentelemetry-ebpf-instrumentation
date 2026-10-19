// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const schemaReleaseBaseURL = "https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/"

func TestSchemaReleaseVersions(t *testing.T) {
	for _, tc := range []struct {
		version string
		valid   bool
	}{
		{"1.0.0", true},
		{"0.0.0", true},
		{"1.0.0-0", true},
		{"1.0.0-rc.0", true},
		{"1.0.0-rc.1", true},
		{"1.0.0-alpha.10", true},
		{"1.0.0-01a", true},
		{"1.0.0-alpha-01", true},
		{"1.0.0+build.123", true},
		{"0.14.0+build.123", true},
		{"1.0.0+build-123", true},
		{"1.0.0+001", true},
		{"1.0.0+build.001", true},
		{"1.0.0-rc.1+build.123", true},
		{"1.0.0-rc.1+build-123", true},
		{"1.0.0-01", false},
		{"1.0.0-rc.01", false},
		{"1.0.0-01.rc", false},
		{"1.0.0-alpha.001", false},
		{"01.0.0", false},
		{"1.01.0", false},
		{"1.0.01", false},
		{"1.0.0-", false},
		{"1.0.0-rc..1", false},
		{"1.0.0+", false},
		{"1.0.0+build..123", false},
		{"1.0.0+build+123", false},
		{"1.0.0+build.", false},
		{"1.0.0+.build", false},
		{"1.0.0+foo_bar", false},
		{"1.0.0-rc.01+build.123", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			root := schemaReleaseFixture(t)
			writeSchemaReleaseFile(t, root, "versions.yaml", "module-sets:\n  obi:\n    version: v"+tc.version+"\n")
			const baseURL = schemaReleaseBaseURL
			manifest := "schema_url: " + baseURL + "0.14.0\n"
			emitted := "var OBISchemaURL = \"" + baseURL + "0.14.0\"\n"
			schema := func(version string) string {
				return fmt.Sprintf("file_format: 1.1.0\nschema_url: %s%s\nversions:\n  %s:\n", baseURL, version, version)
			}

			out, err := exec.Command("bash", filepath.Join(root, "scripts/generate-schema-next.sh")).CombinedOutput()
			if tc.valid {
				require.NoError(t, err, "%s", out)
				version, _, _ := strings.Cut(tc.version, "+")
				if strings.ContainsAny(tc.version, "-+") {
					require.NoFileExists(t, filepath.Join(root, "site/schemas/obi", tc.version))
				}
				if strings.Contains(version, "-") {
					for path, expected := range map[string]string{
						"schemas/obi/manifest.yaml":                     manifest,
						"pkg/export/attributes/names/schema_version.go": emitted,
					} {
						contents, readErr := os.ReadFile(filepath.Join(root, path))
						require.NoError(t, readErr)
						require.Equal(t, expected, string(contents))
					}
				} else {
					contents, readErr := os.ReadFile(filepath.Join(root, "site/schemas/obi", version))
					require.NoError(t, readErr)
					require.Contains(t, string(contents), "schema_url: "+baseURL+version+"\n")
					require.Contains(t, string(contents), "  "+version+":\n")
					contents, readErr = os.ReadFile(filepath.Join(root, "schemas/obi/manifest.yaml"))
					require.NoError(t, readErr)
					require.Equal(t, "schema_url: "+baseURL+version+"\n", string(contents))
					contents, readErr = os.ReadFile(filepath.Join(root, "pkg/export/attributes/names/schema_version.go"))
					require.NoError(t, readErr)
					require.Contains(t, string(contents), "var OBISchemaURL = \""+baseURL+version+"\"\n")
				}
			} else {
				require.Error(t, err, "%s", out)
				require.Contains(t, string(out), "versions.yaml obi version")
				require.NoFileExists(t, filepath.Join(root, "site/schemas/obi", tc.version))
				contents, readErr := os.ReadFile(filepath.Join(root, "schemas/obi/manifest.yaml"))
				require.NoError(t, readErr)
				require.Equal(t, manifest, string(contents))
				contents, readErr = os.ReadFile(filepath.Join(root, "pkg/export/attributes/names/schema_version.go"))
				require.NoError(t, readErr)
				require.Equal(t, emitted, string(contents))

				writeSchemaReleaseFile(t, root, "site/schemas/obi/"+tc.version, schema(tc.version))
				writeSchemaReleaseFile(t, root, "schemas/obi/manifest.yaml", "schema_url: "+baseURL+tc.version+"\n")
				writeSchemaReleaseFile(t, root, "pkg/export/attributes/names/schema_version.go", "var OBISchemaURL = \""+baseURL+tc.version+"\"\n")
			}

			out, err = exec.Command("bash", filepath.Join(root, "scripts/check-schema-files.sh")).CombinedOutput()
			if tc.valid {
				require.NoError(t, err, "%s", out)
			} else {
				require.Error(t, err, "%s", out)
				require.Contains(t, string(out), "name is not a MAJOR.MINOR.PATCH version")
			}
		})
	}
}

func TestSchemaReleaseCandidateToStable(t *testing.T) {
	root := schemaReleaseFixture(t)
	previous, err := os.ReadFile(filepath.Join(root, "site/schemas/obi/0.14.0"))
	require.NoError(t, err)
	for _, version := range []string{"1.0.0-rc.1+build.1", "1.0.0-rc.2+build.2", "1.0.0+build.3"} {
		writeSchemaReleaseFile(t, root, "versions.yaml", "module-sets:\n  obi:\n    version: v"+version+"\n")
		out, runErr := exec.Command("bash", filepath.Join(root, "scripts/generate-schema-next.sh")).CombinedOutput()
		require.NoError(t, runErr, "%s", out)
		out, runErr = exec.Command("bash", filepath.Join(root, "scripts/check-schema-files.sh")).CombinedOutput()
		require.NoError(t, runErr, "%s", out)
	}
	require.NoFileExists(t, filepath.Join(root, "site/schemas/obi/1.0.0-rc.1"))
	require.NoFileExists(t, filepath.Join(root, "site/schemas/obi/1.0.0-rc.2"))
	final, err := os.ReadFile(filepath.Join(root, "site/schemas/obi/1.0.0"))
	require.NoError(t, err)
	_, history, found := strings.Cut(string(previous), "versions:\n")
	require.True(t, found)
	require.Equal(t, "file_format: 1.1.0\nschema_url: "+schemaReleaseBaseURL+"1.0.0\nversions:\n  1.0.0:\n"+history, string(final))
	preserved, err := os.ReadFile(filepath.Join(root, "site/schemas/obi/0.14.0"))
	require.NoError(t, err)
	require.Equal(t, previous, preserved)

	final = []byte(strings.Replace(string(final), "  1.0.0:\n", "  1.0.0:\n    all:\n      changes:\n        - rename_attributes:\n            attribute_map:\n              old.name: new.name\n", 1))
	writeSchemaReleaseFile(t, root, "site/schemas/obi/1.0.0", string(final))
	for _, version := range []string{"1.0.0+build.4", "1.0.0"} {
		writeSchemaReleaseFile(t, root, "versions.yaml", "module-sets:\n  obi:\n    version: v"+version+"\n")
		out, runErr := exec.Command("bash", filepath.Join(root, "scripts/generate-schema-next.sh")).CombinedOutput()
		require.NoError(t, runErr, "%s", out)
		preserved, err = os.ReadFile(filepath.Join(root, "site/schemas/obi/1.0.0"))
		require.NoError(t, err)
		require.Equal(t, final, preserved)
	}
}

func TestSchemaReleaseRejectsPrereleaseSchemas(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		contents string
		message  string
	}{
		{"file", "site/schemas/obi/1.0.0-rc.1", "file_format: 1.1.0\nschema_url: " + schemaReleaseBaseURL + "1.0.0-rc.1\nversions:\n  1.0.0-rc.1:\n", "name is not a MAJOR.MINOR.PATCH version"},
		{"history", "site/schemas/obi/0.14.0", "file_format: 1.1.0\nschema_url: " + schemaReleaseBaseURL + "0.14.0\nversions:\n  0.14.0:\n  1.0.0-rc.1:\n", "versions: entry '1.0.0-rc.1'"},
		{"emitted URL", "pkg/export/attributes/names/schema_version.go", "var OBISchemaURL = \"" + schemaReleaseBaseURL + "0.14.0-rc.1\"\n", "OBISchemaURL must name a stable"},
		{"manifest URL", "schemas/obi/manifest.yaml", "schema_url: " + schemaReleaseBaseURL + "0.14.0-rc.1\n", "does not match OBISchemaURL"},
		{"stable release with stale schema", "versions.yaml", "module-sets:\n  obi:\n    version: v1.0.0\n", "does not match the versions.yaml version"},
		{"build release with stale schema", "versions.yaml", "module-sets:\n  obi:\n    version: v1.0.0+build-123\n", "does not match the versions.yaml version"},
		{"invalid release", "versions.yaml", "module-sets:\n  obi:\n    version: v1.0.0-01\n", "versions.yaml obi version '1.0.0-01' is invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := schemaReleaseFixture(t)
			writeSchemaReleaseFile(t, root, tc.path, tc.contents)
			out, err := exec.Command("bash", filepath.Join(root, "scripts/check-schema-files.sh")).CombinedOutput()
			require.Error(t, err, "%s", out)
			require.Contains(t, string(out), tc.message)
		})
	}
}

func TestSchemaReleaseRejectsNoncanonicalURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"bare version", "0.14.0"},
		{"relative path", "schemas/obi/0.14.0"},
		{"other host", "https://example.com/schemas/obi/0.14.0"},
		{"HTTP", strings.Replace(schemaReleaseBaseURL, "https:", "http:", 1) + "0.14.0"},
		{"query", schemaReleaseBaseURL + "0.14.0?build=123"},
		{"trailing slash", schemaReleaseBaseURL + "0.14.0/"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := schemaReleaseFixture(t)
			writeSchemaReleaseFile(t, root, "pkg/export/attributes/names/schema_version.go", "var OBISchemaURL = \""+tc.url+"\"\n")
			writeSchemaReleaseFile(t, root, "schemas/obi/manifest.yaml", "schema_url: "+tc.url+"\n")
			out, err := exec.Command("bash", filepath.Join(root, "scripts/check-schema-files.sh")).CombinedOutput()
			require.Error(t, err, "%s", out)
			require.Contains(t, string(out), "OBISchemaURL")
		})
	}
}

func schemaReleaseFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, script := range []string{"generate-schema-next.sh", "check-schema-files.sh"} {
		contents, err := os.ReadFile(script)
		require.NoError(t, err)
		writeSchemaReleaseFile(t, root, "scripts/"+script, string(contents))
	}
	writeSchemaReleaseFile(t, root, "versions.yaml", "module-sets:\n  obi:\n    version: v1.0.0-rc.1\n")
	writeSchemaReleaseFile(t, root, "schemas/obi/manifest.yaml", "schema_url: "+schemaReleaseBaseURL+"0.14.0\n")
	writeSchemaReleaseFile(t, root, "pkg/export/attributes/names/schema_version.go", "var OBISchemaURL = \""+schemaReleaseBaseURL+"0.14.0\"\n")
	previous, err := os.ReadFile("../site/schemas/obi/0.14.0")
	require.NoError(t, err)
	writeSchemaReleaseFile(t, root, "site/schemas/obi/0.14.0", string(previous))
	return root
}

func writeSchemaReleaseFile(t *testing.T, root, path, contents string) {
	t.Helper()
	path = filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
}
