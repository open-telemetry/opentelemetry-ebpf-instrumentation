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

const expectedDNSDuplicate = `[{
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateMetricName": {
		"metric_name": "dns.lookup.duration",
		"provenances": [
			{"path": ".deps/upstream-v1.41.0/model/dns/metrics.yaml"},
			{"path": "/obi-registry/groups/dns.yaml"}
		]
	}}
}]`

func TestLintSchemaFilterAllowsExpectedDNSDuplicate(t *testing.T) {
	remaining := runLintSchemaFilter(t, expectedDNSDuplicate)
	if len(remaining) != 0 {
		t.Fatalf("expected the documented dns.lookup.duration duplicate to be filtered, got %d diagnostics", len(remaining))
	}
}

// expectedEnumOverrideDuplicates mirrors the DuplicateAttributeId diagnostics
// weaver emits for the attribute overrides in schemas/obi/groups/ (see
// schemas/obi/README.md).
const expectedEnumOverrideDuplicates = `[{
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "messaging.system",
		"group_ids": ["registry.messaging", "x.obi.messaging"]
	}}
}, {
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "gen_ai.provider.name",
		"group_ids": ["registry.gen_ai", "x.obi.gen_ai"]
	}}
}, {
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "gen_ai.operation.name",
		"group_ids": ["registry.gen_ai", "x.obi.gen_ai"]
	}}
}, {
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "openai.api.type",
		"group_ids": ["registry.openai", "x.obi.openai"]
	}}
}, {
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "telemetry.sdk.language",
		"group_ids": ["registry.telemetry", "x.obi.telemetry"]
	}}
}, {
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "db.system.name",
		"group_ids": ["registry.db", "x.obi.db"]
	}}
}, {
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "rpc.system.name",
		"group_ids": ["registry.rpc", "x.obi.rpc"]
	}}
}, {
	"diagnostic": {"severity": "Error"},
	"error": {"DuplicateAttributeId": {
		"attribute_id": "error.type",
		"group_ids": ["registry.error", "x.obi.error"]
	}}
}]`

func TestLintSchemaFilterAllowsExpectedEnumOverrideDuplicates(t *testing.T) {
	remaining := runLintSchemaFilter(t, expectedEnumOverrideDuplicates)
	if len(remaining) != 0 {
		t.Fatalf("expected the documented enum-override attribute duplicates to be filtered, got %d diagnostics", len(remaining))
	}
}

func TestLintSchemaFilterKeepsUnrelatedDiagnostics(t *testing.T) {
	cases := map[string]string{
		"duplicate of another metric": `[{
			"error": {"DuplicateMetricName": {
				"metric_name": "http.server.request.duration",
				"provenances": [
					{"path": ".deps/upstream-v1.41.0/model/http/metrics.yaml"},
					{"path": "/obi-registry/groups/dns.yaml"}
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
					{"path": "/obi-registry/groups/dns.yaml"},
					{"path": "/obi-registry/groups/extra.yaml"}
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
