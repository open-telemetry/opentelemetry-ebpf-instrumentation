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
	Name       string                 `yaml:"name"`
	On         DynamicSpanTarget      `yaml:"on"`
	Attributes []DynamicSpanAttribute `yaml:"attributes,omitempty"`
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
	Argument DynamicArgument `yaml:"argument"`
	Value    string          `yaml:"value"`
}

// DynamicArgument identifies a USDT probe argument by its zero-based index.
type DynamicArgument struct {
	Index *uint8 `yaml:"index,omitempty"`
}

// DynamicArgumentType is the source representation used to decode an argument.
type DynamicArgumentType string

const (
	DynamicArgumentU8     DynamicArgumentType = "u8"
	DynamicArgumentU16    DynamicArgumentType = "u16"
	DynamicArgumentU32    DynamicArgumentType = "u32"
	DynamicArgumentU64    DynamicArgumentType = "u64"
	DynamicArgumentI8     DynamicArgumentType = "i8"
	DynamicArgumentI16    DynamicArgumentType = "i16"
	DynamicArgumentI32    DynamicArgumentType = "i32"
	DynamicArgumentI64    DynamicArgumentType = "i64"
	DynamicArgumentString DynamicArgumentType = "string"
)

// DynamicSpanAttribute maps one explicitly selected argument to a span
// attribute. Argument.Type describes source decoding, not output conversion.
type DynamicSpanAttribute struct {
	Name     string                       `yaml:"name"`
	Argument DynamicSpanAttributeArgument `yaml:"argument"`
}

// DynamicSpanAttributeArgument selects an argument and optionally describes
// its source decoding; runtime/probe metadata may supply the type when absent.
type DynamicSpanAttributeArgument struct {
	Index *uint8              `yaml:"index,omitempty"`
	Type  DynamicArgumentType `yaml:"type,omitempty"`
}
