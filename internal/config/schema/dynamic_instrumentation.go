// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import "go.opentelemetry.io/obi/pkg/appolly/services"

// DynamicInstrumentation declares shared, language-neutral dynamic
// instrumentation rules. Parsing this section does not apply the rules.
type DynamicInstrumentation struct {
	Rules []DynamicInstrumentationRule `yaml:"rules,omitempty"`
}

// DynamicInstrumentationRule selects services and names the spans to add.
type DynamicInstrumentationRule struct {
	Service services.GlobDefinitionCriteria `yaml:"service"`
	Spans   []DynamicSpanSpec               `yaml:"spans"`
}

// DynamicSpanSpec declares a named span and its probe target.
type DynamicSpanSpec struct {
	Name       string                          `yaml:"name"`
	On         DynamicSpanTarget               `yaml:"on"`
	Attributes map[string]DynamicSpanAttribute `yaml:"attributes,omitempty"`
}

// DynamicSpanTarget is one of the four language-neutral probe forms. Function
// symbols are interpreted by the target language's runtime.
type DynamicSpanTarget struct {
	USDTNoRet     string            `yaml:"usdt_noret,omitempty"`
	USDTSpan      string            `yaml:"usdt_span,omitempty"`
	FunctionNoRet string            `yaml:"function_noret,omitempty"`
	Function      *DynamicFunction  `yaml:"function,omitempty"`
	Match         *DynamicSpanMatch `yaml:"match,omitempty"`
}

// DynamicFunction identifies a callable and optionally its ordered parameter
// types, which disambiguate overloaded functions.
type DynamicFunction struct {
	Name       string   `yaml:"name"`
	Parameters []string `yaml:"parameters,omitempty"`
}

// DynamicArgument identifies one function parameter or probe argument. Exactly
// one of Index or Name should be set. Indexes are limited to the first 12
// arguments; name resolution requires runtime metadata that exposes names.
type DynamicArgument struct {
	Index *uint8 `yaml:"index,omitempty"`
	Name  string `yaml:"name,omitempty"`
}

// DynamicSpanMatch filters USDT events by a string-valued probe argument.
type DynamicSpanMatch struct {
	Argument DynamicArgument `yaml:"argument"`
	Value    string          `yaml:"value"`
}

// DynamicSpanAttribute extracts one explicitly selected argument as a span
// attribute. Other arguments are not captured implicitly. Type names use the
// OpenTelemetry attribute types. If omitted, type may be inferred from
// USDT probe metadata; callable argument captures require an explicit type.
type DynamicSpanAttribute struct {
	Argument DynamicArgument `yaml:"argument"`
	Type     string          `yaml:"type,omitempty"`
}
