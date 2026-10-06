// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
		{"1.0.0-01", false},
		{"1.0.0-rc.01", false},
		{"1.0.0-01.rc", false},
		{"1.0.0-alpha.001", false},
		{"01.0.0", false},
		{"1.01.0", false},
		{"1.0.01", false},
		{"1.0.0-", false},
		{"1.0.0-rc..1", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			root := t.TempDir()
			for _, script := range []string{"generate-schema-next.sh", "check-schema-files.sh"} {
				contents, err := os.ReadFile(script)
				require.NoError(t, err)
				writeSchemaReleaseFile(t, root, "scripts/"+script, string(contents))
			}
			writeSchemaReleaseFile(t, root, "versions.yaml", "module-sets:\n  obi:\n    version: v"+tc.version+"\n")
			const baseURL = "https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/"
			manifest := "schema_url: " + baseURL + "0.14.0\n"
			emitted := "var OBISchemaURL = \"" + baseURL + "0.14.0\"\n"
			writeSchemaReleaseFile(t, root, "schemas/obi/manifest.yaml", manifest)
			writeSchemaReleaseFile(t, root, "pkg/export/attributes/names/schema_version.go", emitted)
			schema := func(version string) string {
				return fmt.Sprintf("file_format: 1.1.0\nschema_url: %s%s\nversions:\n  %s:\n", baseURL, version, version)
			}
			writeSchemaReleaseFile(t, root, "site/schemas/obi/0.14.0", schema("0.14.0"))

			out, err := exec.Command("bash", filepath.Join(root, "scripts/generate-schema-next.sh")).CombinedOutput()
			if tc.valid {
				require.NoError(t, err, "%s", out)
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

func writeSchemaReleaseFile(t *testing.T, root, path, contents string) {
	t.Helper()
	path = filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
}
