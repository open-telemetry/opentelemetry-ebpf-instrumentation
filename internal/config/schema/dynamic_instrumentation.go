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
	Name  string                          `yaml:"name"`
	On    DynamicSpanTarget               `yaml:"on"`
	Attrs map[string]DynamicSpanAttribute `yaml:"attrs,omitempty"`
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

// DynamicSpanMatch filters USDT events by a string-valued probe argument.
type DynamicSpanMatch struct {
	Arg   uint8  `yaml:"arg"`
	Value string `yaml:"value"`
}

// DynamicSpanAttribute extracts a probe argument as a span attribute. USDT
// integer types may be inferred from the probe metadata; function targets
// require an explicit type.
type DynamicSpanAttribute struct {
	Arg  uint8  `yaml:"arg"`
	Type string `yaml:"type,omitempty"`
}
