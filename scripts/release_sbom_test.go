// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const releaseSBOMFixture = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "archive", "version": "VERSION"}},
  "components": [
    {"bom-ref": "pkg:golang/go.opentelemetry.io/obi@v1.0.0-rc?package-id=core",
     "name": "go.opentelemetry.io/obi", "version": "v1.0.0-rc",
     "purl": "pkg:golang/go.opentelemetry.io/obi@v1.0.0-rc"},
    {"bom-ref": "collector", "name": "go.opentelemetry.io/obi/collector", "version": "v0.15.2",
     "purl": "pkg:golang/go.opentelemetry.io/obi/collector@v0.15.2"},
    {"bom-ref": "agent-import", "name": "obi-java-agent", "version": "VERSION",
     "purl": "pkg:maven/io.opentelemetry.obi/obi-java-agent@VERSION"},
    {"bom-ref": "buddy-import", "name": "byte-buddy", "version": "1.18.14-jdk5",
     "purl": "pkg:maven/net.bytebuddy/byte-buddy@1.18.14-jdk5"}
  ],
  "dependencies": [
    {"ref": "pkg:golang/go.opentelemetry.io/obi@v1.0.0-rc?package-id=core", "dependsOn": ["collector"]},
    {"ref": "archive", "dependsOn": ["pkg:golang/go.opentelemetry.io/obi@v1.0.0-rc?package-id=core", "agent-import"]},
    {"ref": "agent-import", "dependsOn": ["buddy-import"]}
  ]
}`

const releaseJavaSBOMFixture = `{
  "metadata": {"component": {"bom-ref": "agent", "name": "obi-java-agent", "version": "VERSION",
    "purl": "pkg:maven/io.opentelemetry.obi/obi-java-agent@VERSION"}},
  "components": [{"bom-ref": "buddy", "name": "byte-buddy", "version": "1.18.14-jdk5",
    "purl": "pkg:maven/net.bytebuddy/byte-buddy@1.18.14-jdk5"}],
  "dependencies": [{"ref": "agent", "dependsOn": ["buddy"]}, {"ref": "buddy", "dependsOn": []}]
}`

func TestReleaseSBOMVersions(t *testing.T) {
	for _, version := range []string{"v1.0.0", "v1.0.0-rc.2", "v1.0.0+build.123", "v1.0.0-rc.2+build.123"} {
		t.Run(version, func(t *testing.T) {
			input := strings.ReplaceAll(releaseSBOMFixture, "VERSION", version)
			out, err := releaseSBOMCommand(t, input, "--arg", "version", version, "-f", "release-sbom.jq")
			require.NoError(t, err, "%s", out)

			var bom struct {
				Components []struct {
					Ref     string `json:"bom-ref"`
					Name    string `json:"name"`
					Version string `json:"version"`
					PURL    string `json:"purl"`
				} `json:"components"`
			}
			require.NoError(t, json.Unmarshal(out, &bom))
			require.Len(t, bom.Components, 4)
			core := bom.Components[0]
			require.Equal(t, version, core.Version)
			require.Equal(t, "pkg:golang/go.opentelemetry.io/obi@"+url.QueryEscape(version), core.PURL)
			require.Equal(t, core.PURL+"?package-id=core", core.Ref)
			require.Equal(t, "v0.15.2", bom.Components[1].Version)
			require.NotContains(t, string(out), "obi@v1.0.0-rc?")
			validateReleaseSBOM(t, string(out), version, "")
		})
	}
}

func TestValidateReleaseSBOMRejectsIncompleteInventory(t *testing.T) {
	const version = "v1.0.0-rc.2"
	input := strings.ReplaceAll(releaseSBOMFixture, "VERSION", version)
	valid, err := releaseSBOMCommand(t, input, "--arg", "version", version, "-f", "release-sbom.jq")
	require.NoError(t, err, "%s", valid)

	for _, tc := range []struct {
		name   string
		filter string
		error  string
	}{
		{"archive version", `.metadata.component.version = "v0.15.2"`, "archive version"},
		{"missing module", `.components |= map(select(.name != "go.opentelemetry.io/obi"))`, "OBI module is missing"},
		{"truncated version", `.components[0].version = "v1.0.0-rc"`, "OBI module version"},
		{"wrong package URL", `.components[0].purl = "pkg:golang/go.opentelemetry.io/obi@v1.0.0-rc"`, "OBI module version"},
		{"missing Java dependency", `.components |= map(select(.name != "byte-buddy"))`, "Java component is missing"},
		{"unknown agent version", `.components[2].version = "UNKNOWN"`, "Java component is missing"},
		{"extra unknown agent", `.components += [(.components[2] | .["bom-ref"] = "unknown-agent" | .version = "UNKNOWN")]`, "Java agent version"},
		{"wrong Java dependency version", `.components[3].version = "1.0.0"`, "Java component is missing"},
		{"missing Java edge", `.dependencies[2].dependsOn = []`, "Java dependency graph is incomplete"},
		{"duplicate reference", `.components += [.components[0]]`, "duplicate component references"},
		{"dangling reference", `.dependencies[1].dependsOn += ["missing"]`, "unresolved dependency reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken, err := releaseSBOMCommand(t, string(valid), tc.filter)
			require.NoError(t, err, "%s", broken)
			validateReleaseSBOM(t, string(broken), version, tc.error)
		})
	}
}

func validateReleaseSBOM(t *testing.T, input, version, wantError string) {
	t.Helper()
	javaPath := filepath.Join(t.TempDir(), "java.cdx.json")
	require.NoError(t, os.WriteFile(javaPath, []byte(strings.ReplaceAll(releaseJavaSBOMFixture, "VERSION", version)), 0o600))
	out, err := releaseSBOMCommand(t, input, "-e", "--arg", "version", version,
		"--slurpfile", "java_sbom", javaPath, "-f", "validate-release-sbom.jq")
	if wantError == "" {
		require.NoError(t, err, "%s", out)
		return
	}
	require.Error(t, err, "%s", out)
	require.Contains(t, string(out), wantError)
}

func releaseSBOMCommand(t *testing.T, input string, args ...string) ([]byte, error) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	cmd := exec.Command("jq", args...)
	cmd.Stdin = strings.NewReader(input)
	return cmd.CombinedOutput()
}
