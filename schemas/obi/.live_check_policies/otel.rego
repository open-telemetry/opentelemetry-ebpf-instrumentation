# Copied unchanged from weaver's default live-check advice policy
# (defaults/policies/live_check_advice/otel.rego at weaver v0.27.0, the pinned
# weaver image). Pointing `advice_policies` at this directory replaces the
# defaults, so they are carried here to keep running. Re-sync it when bumping
# the weaver image.
package live_check_advice

import rego.v1

# Use pre-computed sets from jq
attributes_set := data.attributes_set

deprecated_attributes_set := data.deprecated_attributes_set

templates_set := data.templates_set

namespaces_to_check_set := data.namespaces_to_check_set

name_regex := "^[a-z][a-z0-9]*([._][a-z0-9]+)*$"

derive_namespaces(name) := [
concat(".", array.slice(parts, 0, i)) |
	parts := split(name, ".")
	count(parts) > 1 # Only derive namespaces if there are at least 2 parts

	# Stop at count(parts)-1 to exclude the full attribute name
	some i in numbers.range(1, count(parts) - 1)
]

# checks attribute has a namespace
deny contains make_advice(advice_type, advice_level, advice_context, message) if {
	input.sample.attribute
	not contains(input.sample.attribute.name, ".")
	advice_type := "missing_namespace"
	advice_level := "improvement"
	advice_context := {"attribute_key": input.sample.attribute.name}
	message := sprintf("Attribute key '%s' must include a namespace (e.g. '{namespace}.{attribute_key}')", [input.sample.attribute.name])
}

# checks attribute name format
deny contains make_advice(advice_type, advice_level, advice_context, message) if {
	input.sample.attribute
	not is_template_type(input.sample.attribute.name)
	not regex.match(name_regex, input.sample.attribute.name)
	advice_type := "invalid_format"
	advice_level := "violation"
	advice_context := {"attribute_key": input.sample.attribute.name}
	message := sprintf("Attribute key '%s' does not match name formatting rules.", [input.sample.attribute.name])
}

# checks metric name format
deny contains make_advice_with_signal_info(advice_type, advice_level, advice_context, signal_name, signal_type, message) if {
	input.sample.metric
	not regex.match(name_regex, input.sample.metric.name)
	advice_type := "invalid_format"
	advice_level := "violation"
	advice_context := {"metric_name": input.sample.metric.name}
	signal_name := input.sample.metric.name
	signal_type := "metric"
	message := sprintf("Metric name '%s' does not match name formatting rules.", [input.sample.metric.name])
}

# checks attribute namespace doesn't collide with existing attributes
deny contains make_advice(advice_type, advice_level, advice_context, message) if {
	input.sample.attribute

	# Skip if no namespace
	contains(input.sample.attribute.name, ".")

	# Get input namespaces
	namespaces := derive_namespaces(input.sample.attribute.name)

	# Find collision
	some ns in namespaces
	attributes_set[ns]
	not deprecated_attributes_set[ns]

	advice_type := "illegal_namespace"
	advice_level := "violation"
	advice_context := {"attribute_key": input.sample.attribute.name, "namespace": ns}
	message := sprintf("Namespace '%s' collides with existing attribute '%s'", [ns, input.sample.attribute.name])
}

# provides advice if the attribute extends an existing namespace
deny contains make_advice(advice_type, advice_level, advice_context, message) if {
	input.sample.attribute

	# Skip checks first (fail fast)
	contains(input.sample.attribute.name, ".") # Must have at least one namespace
	not is_template_type(input.sample.attribute.name)
	not attributes_set[input.sample.attribute.name]

	# Get input namespaces
	namespaces := derive_namespaces(input.sample.attribute.name)

	# Find matches - check keys in set
	matches := [ns | some ns in namespaces; namespaces_to_check_set[ns]]
	count(matches) > 0

	# Get the last match (most specific namespace)
	namespace := matches[count(matches) - 1]

	advice_type := "extends_namespace"
	advice_level := "information"
	advice_context := {"attribute_key": input.sample.attribute.name, "namespace": namespace}
	message := sprintf("Attribute key '%s' collides with existing namespace '%s'", [input.sample.attribute.name, namespace])
}

make_advice(advice_type, advice_level, advice_context, message) := {
	"type": "advice",
	"advice_type": advice_type,
	"advice_level": advice_level,
	"advice_context": advice_context,
	"message": message,
}

make_advice_with_signal_info(advice_type, advice_level, advice_context, signal_name, signal_type, message) := {
	"type": "advice",
	"advice_type": advice_type,
	"advice_level": advice_level,
	"advice_context": advice_context,
	"signal_name": signal_name,
	"signal_type": signal_type,
	"message": message,
}

# Helper function to check if name is a template type, extending it across a dot
is_template_type(name) if {
	some template in object.keys(templates_set)
	prefix := concat("", [trim_suffix(template, "."), "."])
	startswith(name, prefix)
	count(name) > count(prefix)
}
