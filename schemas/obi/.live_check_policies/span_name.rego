# Compares the name of every matched span with the name its span definition
# declares: the first of its `name.templates` whose attributes are all present,
# non-empty and not `_OTHER`, rendered with the span's attribute values. OBI
# reports `server.port` as 0 when it observed no port, so a 0 port counts as
# absent too. As in a URL, an IPv6 `server.address` is bracketed when the
# template joins it with `server.port`. A span definition that describes its
# name only in a note is not checked.
package live_check_advice

import rego.v1

deny contains span_name_finding(span, signal, template, expected) if {
	span := input.sample.span
	signal := input.registry_group
	signal != null
	templates := signal.name.templates

	values := {attr.name: sprintf("%v", [attr.value]) |
		some attr in span.attributes
		attr.value != null
	}

	applicable := [i | some i, t in templates; template_applies(t, values)]
	count(applicable) > 0
	template := templates[min(applicable)]

	expected := concat("", [part_text(part, values, template) | some part in template.parts])
	expected != span.name
}

template_applies(template, values) if {
	every key in template.attributes {
		values[key] != ""
		values[key] != "_OTHER"
		not unobserved_port(key, values[key])
	}
}

unobserved_port(key, value) if {
	key == "server.port"
	value == "0"
}

part_text(part, _, _) := part.value if part.type == "literal"

part_text(part, values, template) := host_with_port(values[part.attribute]) if {
	part.type == "attribute"
	part.attribute == "server.address"
	"server.port" in template.attributes
} else := values[part.attribute] if {
	part.type == "attribute"
}

host_with_port(address) := sprintf("[%s]", [address]) if {
	contains(address, ":")
} else := address

span_name_finding(span, signal, template, expected) := {
	"id": "span_name_mismatch",
	"level": "violation",
	"signal_type": "span",
	"signal_name": span.name,
	"context": {
		"span_name": span.name,
		"expected_span_name": expected,
		"template": template.pattern,
		"span_type": signal.type,
	},
	"message": sprintf(
		"Span name '%s' does not match '%s', rendered from the template '%s' of span '%s'.",
		[span.name, expected, template.pattern, signal.type],
	),
}
