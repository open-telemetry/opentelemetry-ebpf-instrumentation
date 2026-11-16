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

// resolvedRegistry mirrors the shape of `weaver registry resolve --v2` output:
// OBI's own signals and attribute groups carry a provenance path inside the
// registry, upstream ones name the semconv schema url as their source.
// `traces.span.metrics.calls` has no `obi` marker in its name, which is why the
// renderer selects on provenance rather than name.
const resolvedRegistry = `{
  "registry": {
    "attribute_groups": [
      {
        "id": "registry.obi",
        "brief": "OBI's own attributes.",
        "stability": "development",
        "provenance": {"path": "/obi-registry/groups/obi_internal/registry.yaml"},
        "attributes": [
          {"key": "obi.version", "type": "string", "stability": "development", "brief": "OBI build version.", "examples": ["v0.42.0"]},
          {"key": "instance", "type": "string", "stability": "development", "brief": "Scrape target instance."}
        ]
      },
      {
        "id": "x.obi.error",
        "brief": "An upstream namespace OBI extends.",
        "stability": "development",
        "provenance": {"path": "/obi-registry/groups/error/registry.yaml"},
        "attributes": [
          {"key": "error.type", "type": "string", "stability": "stable", "brief": "Error class | with a pipe."},
          {"key": "obi.small.enum", "type": {"members": [{"id": "a", "value": "a"}, {"id": "b", "value": "b"}]}, "stability": "development", "brief": "A short enum."},
          {"key": "obi.long.enum", "type": {"members": [{"value": "v1"}, {"value": "v2"}, {"value": "v3"}, {"value": "v4"}, {"value": "v5"}, {"value": "v6"}, {"value": "v7"}, {"value": "v8"}, {"value": "v9"}, {"value": "v10"}]}, "stability": "development", "brief": "A long enum."},
          {"key": "obi.enum.with.examples", "type": {"members": [{"value": "m1"}, {"value": "m2"}]}, "stability": "development", "brief": "Enum that declares examples.", "examples": ["chosen"]}
        ]
      },
      {
        "id": "registry.http",
        "brief": "Upstream semconv attributes.",
        "stability": "stable",
        "provenance": {"source": "https://opentelemetry.io/schemas/1.41.0", "path": ".deps/upstream-v1.41.0/model/http/registry.yaml"},
        "attributes": [{"key": "http.route", "type": "string", "stability": "stable", "brief": "Route."}]
      }
    ],
    "metrics": [
      {
        "name": "traces.span.metrics.calls",
        "brief": "Span metrics call count.",
        "instrument": "counter",
        "unit": "",
        "stability": "development",
        "provenance": {"path": "/obi-registry/groups/spanmetrics/metrics.yaml"},
        "attributes": [{"key": "span.name", "type": "string", "stability": "development", "brief": "Span name.", "requirement_level": "required"}]
      },
      {
        "name": "obi.renamed.metric",
        "brief": "A metric that was renamed.",
        "instrument": "counter",
        "unit": "1",
        "stability": "development",
        "deprecated": {"reason": "renamed", "renamed_to": "obi.new.metric"},
        "provenance": {"path": "/obi-registry/groups/spanmetrics/metrics.yaml"}
      },
      {
        "name": "http.server.request.duration",
        "brief": "Upstream metric.",
        "instrument": "histogram",
        "unit": "s",
        "stability": "stable",
        "provenance": {"source": "https://opentelemetry.io/schemas/1.41.0", "path": ".deps/upstream-v1.41.0/model/http/metrics.yaml"}
      }
    ],
    "spans": [
      {
        "type": "obi.example.client",
        "kind": "client",
        "name": {
          "templates": [
            {"pattern": "{obi.scalar.examples} {error.type}", "attributes": ["obi.scalar.examples", "error.type"], "parts": []},
            {"pattern": "EXAMPLE", "attributes": [], "parts": []}
          ],
          "note": "A note on the name."
        },
        "brief": "An OBI span.",
        "stability": "development",
        "provenance": {"path": "/obi-registry/groups/example/spans.yaml"},
        "attributes": [
          {"key": "obi.scalar.examples", "type": "string", "stability": "development", "brief": "Declares examples as a bare scalar.", "examples": "gpt-4"},
          {"key": "error.type", "type": "string", "stability": "stable", "brief": "Error class.", "requirement_level": {"conditionally_required": "if the operation failed"}}
        ]
      },
      {
        "type": "http.client",
        "kind": "client",
        "name": {"note": "Upstream name."},
        "brief": "Upstream span.",
        "stability": "stable",
        "provenance": {"source": "https://opentelemetry.io/schemas/1.41.0", "path": ".deps/upstream-v1.41.0/model/http/spans.yaml"}
      }
    ]
  }
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
	if !strings.Contains(attributes, "| `error.type` | string |") {
		t.Errorf("the OBI override of error.type was not rendered as a string\n%s", attributes)
	}

	readme := renderSchemaDocs(t, "readme")
	if !strings.Contains(readme, "2 attribute groups") || !strings.Contains(readme, "2 metrics") {
		t.Errorf("readme counts do not match the fixture\n%s", readme)
	}
	if !strings.Contains(readme, "1 spans") {
		t.Errorf("readme does not count the fixture's span\n%s", readme)
	}
}

func TestSchemaDocsSpansSelectsOBIGroupsOnly(t *testing.T) {
	page := renderSchemaDocs(t, "spans")

	if !strings.Contains(page, "## `obi.example.client`") {
		t.Errorf("spans page dropped an OBI span\n%s", page)
	}
	// The kind is part of the contract, so it is documented alongside the span.
	if !strings.Contains(page, "| client | development |") {
		t.Errorf("spans page did not document the span kind\n%s", page)
	}
	if strings.Contains(page, "## `http.client`") {
		t.Errorf("spans page leaked an upstream span\n%s", page)
	}
}

func TestSchemaDocsRendersScalarExamples(t *testing.T) {
	// `examples` is a list in most declarations but a bare scalar in some
	// upstream ones; iterating it blindly aborts the whole render.
	page := renderSchemaDocs(t, "spans")

	if !strings.Contains(page, "| `obi.scalar.examples` | string | `recommended` | development | Declares examples as a bare scalar. | gpt-4 |") {
		t.Errorf("a scalar examples declaration did not render\n%s", page)
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

// A span documents how OBI names it: its templates in the order they are tried,
// and the note that describes whatever the templates cannot express.
func TestSchemaDocsRendersSpanNames(t *testing.T) {
	page := renderSchemaDocs(t, "spans")

	want := "Name, from the first template that applies: `{obi.scalar.examples} {error.type}`, `EXAMPLE`. Name: A note on the name."
	if !strings.Contains(page, want) {
		t.Errorf("spans page did not document the span name\n%s", page)
	}
}

func TestSchemaDocsRendersConditionalRequirementLevels(t *testing.T) {
	page := renderSchemaDocs(t, "spans")

	if !strings.Contains(page, "| `error.type` | string | `conditionally_required`: if the operation failed | stable | Error class. |  |") {
		t.Errorf("a conditional requirement level did not render with its condition\n%s", page)
	}
}
