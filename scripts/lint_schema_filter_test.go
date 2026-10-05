// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// runLintSchemaFilter pipes a diagnostics JSON document through
// lint-schema-filter.jq and returns the surviving diagnostics.
func runLintSchemaFilter(t *testing.T, diagnostics string) []json.RawMessage {
	t.Helper()

	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}

	cmd := exec.Command("jq", "-f", "lint-schema-filter.jq")
	cmd.Stdin = strings.NewReader(diagnostics)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jq failed: %v\n%s", err, out)
	}

	var remaining []json.RawMessage
	if err := json.Unmarshal(out, &remaining); err != nil {
		t.Fatalf("filter output is not a JSON array: %v\n%s", err, out)
	}
	return remaining
}

const expectedUnstable = `[{
	"diagnostic": {"severity": "Error"},
	"error": {"FailToResolveDefinition": {"UnstableFileFormat" :{
		"file_format": "definition/2",
		"provenances": "/obi-registry/groups/resource.yaml"
	}}}
}]`

func TestLintSchemaFilterAllowsExpectedUnstable(t *testing.T) {
	remaining := runLintSchemaFilter(t, expectedUnstable)
	if len(remaining) != 0 {
		t.Fatalf("expected the documented unstable error to be filtered, got %d diagnostics", len(remaining))
	}
}

// expectedDeprecatedIncludeUnreferenced mirrors the diagnostic weaver 0.25
// emits (promoted to Error by --future) for the deprecated
// --include-unreferenced flag. OBI no longer relies on the flag, but the
// filter still drops the notice defensively.
const expectedDeprecatedIncludeUnreferenced = `[{
	"diagnostic": {"severity": "Error"},
	"error": {"DeprecatedIncludeUnreferencedWarning": {}}
}]`

func TestLintSchemaFilterAllowsDeprecatedIncludeUnreferenced(t *testing.T) {
	remaining := runLintSchemaFilter(t, expectedDeprecatedIncludeUnreferenced)
	if len(remaining) != 0 {
		t.Fatalf("expected the deprecated include-unreferenced warning to be filtered, got %d diagnostics", len(remaining))
	}
}

func TestLintSchemaFilterKeepsUnrelatedDiagnostics(t *testing.T) {
	cases := map[string]string{
		"attribute override duplicate": `[{
			"diagnostic": {"severity": "Error"},
			"error": {"DuplicateAttributeId": {
				"attribute_id": "error.type",
				"group_ids": ["registry.error", "x.obi.error"]
			}}
		}]`,
		"dns metric duplicate": `[{
			"diagnostic": {"severity": "Error"},
			"error": {"DuplicateMetricName": {
				"metric_name": "dns.lookup.duration",
				"provenances": [
					{"path": "/obi-registry/groups/dns/metrics.yaml"},
					{"path": ".deps/upstream-v1.41.0/model/dns/metrics.yaml"}
				]
			}}
		}]`,
		"duplicate of another metric": `[{
			"error": {"DuplicateMetricName": {
				"metric_name": "http.server.request.duration",
				"provenances": [
					{"path": ".deps/upstream-v1.41.0/model/http/metrics.yaml"},
					{"path": "/obi-registry/groups/dns/metrics.yaml"}
				]
			}}
		}]`,
		"dns duplicate with unexpected provenances": `[{
			"error": {"DuplicateMetricName": {
				"metric_name": "dns.lookup.duration",
				"provenances": [
					{"path": "/obi-registry/groups/a.yaml"},
					{"path": "/obi-registry/groups/b.yaml"}
				]
			}}
		}]`,
		"dns duplicate declared a third time": `[{
			"error": {"DuplicateMetricName": {
				"metric_name": "dns.lookup.duration",
				"provenances": [
					{"path": ".deps/upstream-v1.41.0/model/dns/metrics.yaml"},
					{"path": "/obi-registry/groups/dns/metrics.yaml"},
					{"path": "/obi-registry/groups/extra.yaml"}
				]
			}}
		}]`,
		"dns duplicate from an unexpected obi file": `[{
			"error": {"DuplicateMetricName": {
				"metric_name": "dns.lookup.duration",
				"provenances": [
					{"path": ".deps/upstream-v1.41.0/model/dns/metrics.yaml"},
					{"path": "/obi-registry/groups/elsewhere.yaml"}
				]
			}}
		}]`,
		"different error type": `[{
			"diagnostic": {"severity": "Error"},
			"error": {"DuplicateGroupId": {"group_id": "metric.dns.lookup.duration"}}
		}]`,
		"attribute duplicate for an undeclared attribute": `[{
			"error": {"DuplicateAttributeId": {
				"attribute_id": "http.request.method",
				"group_ids": ["registry.http", "x.obi.http"]
			}}
		}]`,
		"attribute duplicate with a non-obi group pair": `[{
			"error": {"DuplicateAttributeId": {
				"attribute_id": "messaging.system",
				"group_ids": ["registry.messaging", "x.obi.something"]
			}}
		}]`,
		"attribute duplicate declared a third time": `[{
			"error": {"DuplicateAttributeId": {
				"attribute_id": "messaging.system",
				"group_ids": ["registry.messaging", "x.obi.messaging", "registry.extra"]
			}}
		}]`,
	}

	for name, diags := range cases {
		t.Run(name, func(t *testing.T) {
			remaining := runLintSchemaFilter(t, diags)
			if len(remaining) != 1 {
				t.Fatalf("expected the diagnostic to survive the filter, got %d remaining", len(remaining))
			}
		})
	}
}
