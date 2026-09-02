// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"os/exec"
	"strings"
	"testing"
)

// renderSchemaDocs pipes the resolved-registry fixture through schema-docs.jq
// and returns the rendered page.
func renderSchemaDocs(t *testing.T, page string) string {
	t.Helper()

	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}

	cmd := exec.Command("jq", "-r", "--arg", "page", page, "-f", "schema-docs.jq")
	cmd.Stdin = strings.NewReader(resolvedRegistry)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jq failed: %v\n%s", err, out)
	}
	return string(out)
}

// resolvedRegistry mirrors the shape of `weaver registry resolve` output: OBI's
// own groups carry OBI's schema_url as their provenance, upstream groups carry
// the semconv one. `traces.span.metrics.calls` has no `obi` marker in its id,
// which is why the renderer selects on provenance rather than id.
const resolvedRegistry = `{
  "groups": [
    {
      "id": "registry.obi",
      "type": "attribute_group",
      "brief": "OBI's own attributes.",
      "lineage": {"provenance": {"schema_url": "https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/0.12.2"}},
      "attributes": [
        {"name": "obi.version", "type": "string", "stability": "development", "brief": "OBI build version.", "examples": ["v0.42.0"]},
        {"name": "instance", "type": "string", "stability": "development", "brief": "Scrape target instance."}
      ]
    },
    {
      "id": "x.obi.error",
      "type": "attribute_group",
      "brief": "An upstream namespace OBI extends.",
      "lineage": {"provenance": {"schema_url": "https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/0.12.2"}},
      "attributes": [
        {"name": "error.type", "type": {"members": []}, "stability": "stable", "brief": "Error class | with a pipe."},
        {"name": "obi.small.enum", "type": {"members": [{"id": "a", "value": "a"}, {"id": "b", "value": "b"}]}, "stability": "development", "brief": "A short enum."},
        {"name": "obi.long.enum", "type": {"members": [{"value": "v1"}, {"value": "v2"}, {"value": "v3"}, {"value": "v4"}, {"value": "v5"}, {"value": "v6"}, {"value": "v7"}, {"value": "v8"}, {"value": "v9"}, {"value": "v10"}]}, "stability": "development", "brief": "A long enum."},
        {"name": "obi.enum.with.examples", "type": {"members": [{"value": "m1"}, {"value": "m2"}]}, "stability": "development", "brief": "Enum that declares examples.", "examples": ["chosen"]}
      ]
    },
    {
      "id": "registry.http",
      "type": "attribute_group",
      "brief": "Upstream semconv attributes.",
      "lineage": {"provenance": {"schema_url": "https://opentelemetry.io/schemas/1.41.0"}},
      "attributes": [{"name": "http.route", "type": "string", "stability": "stable", "brief": "Route."}]
    },
    {
      "id": "metric.traces_span_metrics_calls",
      "type": "metric",
      "metric_name": "traces.span.metrics.calls",
      "brief": "Span metrics call count.",
      "instrument": "counter",
      "unit": "",
      "stability": "development",
      "lineage": {"provenance": {"schema_url": "https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/0.12.2"}},
      "attributes": [{"name": "span.name", "type": "string", "stability": "development", "brief": "Span name."}]
    },
    {
      "id": "metric.obi_renamed_metric",
      "type": "metric",
      "metric_name": "obi.renamed.metric",
      "brief": "A metric that was renamed.",
      "instrument": "counter",
      "unit": "1",
      "stability": "development",
      "deprecated": {"reason": "renamed", "renamed_to": "obi.new.metric"},
      "lineage": {"provenance": {"schema_url": "https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/0.12.2"}},
      "attributes": []
    },
    {
      "id": "metric.http.server.request.duration",
      "type": "metric",
      "metric_name": "http.server.request.duration",
      "brief": "Upstream metric.",
      "instrument": "histogram",
      "unit": "s",
      "stability": "stable",
      "lineage": {"provenance": {"schema_url": "https://opentelemetry.io/schemas/1.41.0"}},
      "attributes": []
    }
  ]
}`

func TestSchemaDocsAttributesSelectsOBIGroupsOnly(t *testing.T) {
	page := renderSchemaDocs(t, "attributes")

	for _, want := range []string{"## `registry.obi`", "## `x.obi.error`", "`obi.version`", "`error.type`"} {
		if !strings.Contains(page, want) {
			t.Errorf("attributes page is missing %q\n%s", want, page)
		}
	}
	if strings.Contains(page, "registry.http") || strings.Contains(page, "http.route") {
		t.Errorf("attributes page leaked upstream semconv groups\n%s", page)
	}
}

func TestSchemaDocsMetricsSelectsByProvenanceNotID(t *testing.T) {
	page := renderSchemaDocs(t, "metrics")

	if !strings.Contains(page, "## `traces.span.metrics.calls`") {
		t.Errorf("metrics page dropped an OBI metric whose id carries no obi marker\n%s", page)
	}
	if strings.Contains(page, "http.server.request.duration") {
		t.Errorf("metrics page leaked an upstream metric\n%s", page)
	}
	// A metric with no unit is documented as unitless rather than blank.
	if !strings.Contains(page, "| counter | 1 | development |") {
		t.Errorf("metrics page did not default a missing unit to 1\n%s", page)
	}
}

func TestSchemaDocsEscapesPipesAndCountsGroups(t *testing.T) {
	attributes := renderSchemaDocs(t, "attributes")
	if !strings.Contains(attributes, `Error class \| with a pipe.`) {
		t.Errorf("a pipe in a brief was not escaped, which breaks the table\n%s", attributes)
	}
	// An enum-typed attribute renders as "enum" rather than as its member object.
	if !strings.Contains(attributes, "| `error.type` | enum |") {
		t.Errorf("enum attribute type was not rendered as enum\n%s", attributes)
	}

	readme := renderSchemaDocs(t, "readme")
	if !strings.Contains(readme, "2 attribute groups") || !strings.Contains(readme, "2 metrics") {
		t.Errorf("readme counts do not match the fixture\n%s", readme)
	}
}

func TestSchemaDocsRendersEnumMembersCapped(t *testing.T) {
	page := renderSchemaDocs(t, "attributes")

	// A short enum lists every member, so the value space is documented.
	if !strings.Contains(page, "| `obi.small.enum` | enum | development | A short enum. | a; b |") {
		t.Errorf("short enum did not list its members\n%s", page)
	}
	// A long enum is truncated, otherwise upstream enums (db.system.name has 42
	// members) would make the table unreadable.
	if !strings.Contains(page, "v1; v2; v3; v4; v5; v6; v7; v8; …") {
		t.Errorf("long enum was not capped\n%s", page)
	}
	if strings.Contains(page, "v9") || strings.Contains(page, "v10") {
		t.Errorf("capped enum leaked members past the limit\n%s", page)
	}
	// Declared examples win over the member list.
	if !strings.Contains(page, "| `obi.enum.with.examples` | enum | development | Enum that declares examples. | chosen |") {
		t.Errorf("declared examples did not take precedence over enum members\n%s", page)
	}
}

func TestSchemaDocsMarksDeprecatedMetrics(t *testing.T) {
	page := renderSchemaDocs(t, "metrics")

	if !strings.Contains(page, "> **renamed** — use `obi.new.metric` instead") {
		t.Errorf("a renamed metric was not marked deprecated, so it reads as current\n%s", page)
	}
	// A metric with no deprecation gets no callout.
	if strings.Contains(page, "## `traces.span.metrics.calls`\n\n> **") {
		t.Errorf("a non-deprecated metric got a deprecation callout\n%s", page)
	}
}
