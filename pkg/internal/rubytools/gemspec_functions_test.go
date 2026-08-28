// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseGemspec(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected serviceMetadata
	}{
		{
			name: "static assignments",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
end`,
			expected: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name:     "static constructor arguments",
			source:   "Gem::Specification.new(\"orders\", \"1.2.3\") do |spec|\nend",
			expected: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "invalid version is omitted",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "next"
end`,
			expected: serviceMetadata{Name: "orders"},
		},
		{
			name: "version assignment in a nested block is ambiguous",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  if enabled
    spec.version = "1.2.3"
  end
end`,
		},
		{
			name: "ambiguous Ruby syntax fails closed",
			source: `items = []
item = 1
items <<item
Gem::Specification.new("orders", "1.2.3") do |spec|
end`,
		},
		{
			name:   "missing name is rejected",
			source: "Gem::Specification.new do |spec|\nend",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, parseGemspec([]byte(test.source)))
		})
	}
}

func TestRubyTopLevelAt(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		end      int
		expected bool
	}{
		{name: "start of file", lines: []string{"ignored"}, end: 0, expected: true},
		{name: "plain preamble", lines: []string{"require bundler", "header"}, end: 1, expected: true},
		{name: "balanced block", lines: []string{"if enabled", "end", "header"}, end: 2, expected: true},
		{name: "open block", lines: []string{"if enabled", "header"}, end: 1, expected: false},
		{name: "unmatched block end", lines: []string{"end", "header"}, end: 1, expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, rubyTopLevelAt(test.lines, test.end))
		})
	}
}

func TestRubyBlockStart(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{name: "brace", line: "items.each {", expected: true},
		{name: "module", line: "module Orders", expected: true},
		{name: "class", line: "class Worker", expected: true},
		{name: "conditional", line: "if enabled", expected: true},
		{name: "do block", line: "items.each do |item|", expected: true},
		{name: "surrounding whitespace", line: "  begin  ", expected: true},
		{name: "plain expression", line: "enabled = true", expected: false},
		{name: "block end", line: "end", expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, rubyBlockStart(test.line))
		})
	}
}

func TestRubyBlockEnd(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{name: "end", line: "end", expected: true},
		{name: "brace", line: "}", expected: true},
		{name: "surrounding whitespace", line: "  end  ", expected: true},
		{name: "conditional end", line: "end if enabled", expected: false},
		{name: "chained brace", line: "}.freeze", expected: false},
		{name: "plain expression", line: "value", expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, rubyBlockEnd(test.line))
		})
	}
}

func TestParseGemspecHeader(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		expectedVar     string
		expectedName    string
		expectedVersion string
		expectedOK      bool
	}{
		{
			name:        "no constructor arguments",
			line:        "Gem::Specification.new do |spec|",
			expectedVar: "spec",
			expectedOK:  true,
		},
		{
			name:        "empty parentheses",
			line:        "Gem::Specification.new() do |spec|",
			expectedVar: "spec",
			expectedOK:  true,
		},
		{
			name:        "spaced empty parentheses",
			line:        "Gem::Specification.new( ) do |spec|",
			expectedVar: "spec",
			expectedOK:  true,
		},
		{
			name:         "name argument",
			line:         "Gem::Specification.new(\"orders\") do |spec|",
			expectedVar:  "spec",
			expectedName: "orders",
			expectedOK:   true,
		},
		{
			name:            "name and version arguments",
			line:            "Gem::Specification.new \"orders\", '1.2.3' do |gem_spec|",
			expectedVar:     "gem_spec",
			expectedName:    "orders",
			expectedVersion: "1.2.3",
			expectedOK:      true,
		},
		{
			name:            "root-qualified constructor",
			line:            "::Gem::Specification.new(\"orders\", \"1.2.3\") do |spec|",
			expectedVar:     "spec",
			expectedName:    "orders",
			expectedVersion: "1.2.3",
			expectedOK:      true,
		},
		{name: "wrong constructor", line: "Other::Specification.new do |spec|"},
		{name: "missing block", line: "Gem::Specification.new(\"orders\")"},
		{name: "missing block variable", line: "Gem::Specification.new do"},
		{name: "invalid block variable", line: "Gem::Specification.new do |Spec|"},
		{name: "dynamic name", line: "Gem::Specification.new(Orders::NAME) do |spec|"},
		{name: "missing comma", line: "Gem::Specification.new(\"orders\" \"1.2.3\") do |spec|"},
		{name: "dynamic version", line: "Gem::Specification.new(\"orders\", Orders::VERSION) do |spec|"},
		{name: "extra argument", line: "Gem::Specification.new(\"orders\", \"1.2.3\", :extra) do |spec|"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			variable, name, version, ok := parseGemspecHeader(test.line)
			assert.Equal(t, test.expectedVar, variable)
			assert.Equal(t, test.expectedName, name)
			assert.Equal(t, test.expectedVersion, version)
			assert.Equal(t, test.expectedOK, ok)
		})
	}
}

func TestGemspecInvocationCount(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected int
	}{
		{name: "absent", line: "Other::Specification.new", expected: 0},
		{name: "canonical", line: "Gem::Specification.new", expected: 1},
		{name: "root qualified", line: "::Gem::Specification.new", expected: 1},
		{name: "multiple", line: "Gem::Specification.new; Gem::Specification.new", expected: 2},
		{name: "nested constant", line: "Other::Gem::Specification.new", expected: 0},
		{name: "longer constant", line: "OtherGem::Specification.new", expected: 0},
		{name: "longer method", line: "Gem::Specification.newer", expected: 0},
		{name: "predicate method", line: "Gem::Specification.new?", expected: 0},
		{name: "bang method", line: "Gem::Specification.new!", expected: 0},
		{name: "assignment method", line: "Gem::Specification.new=", expected: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, gemspecInvocationCount(test.line))
		})
	}
}

func TestRubyConstantBoundary(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		index    int
		expected bool
	}{
		{name: "start of line", line: "Gem", index: 0, expected: true},
		{name: "root qualifier", line: "::Gem", index: 2, expected: true},
		{name: "root qualifier after punctuation", line: "(::Gem", index: 3, expected: true},
		{name: "namespace qualifier", line: "A::Gem", index: 3, expected: false},
		{name: "word prefix", line: "AGem", index: 1, expected: false},
		{name: "symbol prefix", line: ":Gem", index: 1, expected: false},
		{name: "punctuation prefix", line: ".Gem", index: 1, expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, rubyConstantBoundary(test.line, test.index))
		})
	}
}

func TestParseGemspecAssignment(t *testing.T) {
	tests := []struct {
		name             string
		line             string
		variable         string
		field            string
		expectedValue    string
		expectedAssigned bool
	}{
		{
			name:             "double-quoted literal",
			line:             `spec.name = "orders"`,
			variable:         "spec",
			field:            "name",
			expectedValue:    "orders",
			expectedAssigned: true,
		},
		{
			name:             "single-quoted frozen literal",
			line:             ` spec.version = '1.2.3'.freeze `,
			variable:         "spec",
			field:            "version",
			expectedValue:    "1.2.3",
			expectedAssigned: true,
		},
		{name: "different variable", line: `other.name = "orders"`, variable: "spec", field: "name"},
		{name: "different field", line: `spec.version = "1.2.3"`, variable: "spec", field: "name"},
		{name: "field-name suffix", line: `spec.name_suffix = "api"`, variable: "spec", field: "name"},
		{name: "comparison", line: `spec.name == "orders"`, variable: "spec", field: "name"},
		{name: "regular expression match", line: `spec.name =~ /orders/`, variable: "spec", field: "name"},
		{
			name:             "reference without assignment",
			line:             "spec.name",
			variable:         "spec",
			field:            "name",
			expectedAssigned: true,
		},
		{
			name:             "compound mutation",
			line:             `spec.name += "-api"`,
			variable:         "spec",
			field:            "name",
			expectedAssigned: true,
		},
		{
			name:             "dynamic value",
			line:             "spec.name = Orders::NAME",
			variable:         "spec",
			field:            "name",
			expectedAssigned: true,
		},
		{
			name:             "literal with trailing expression",
			line:             `spec.name = "orders" + suffix`,
			variable:         "spec",
			field:            "name",
			expectedAssigned: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, assigned := parseGemspecAssignment(test.line, test.variable, test.field)
			assert.Equal(t, test.expectedValue, value)
			assert.Equal(t, test.expectedAssigned, assigned)
		})
	}
}

func TestGemspecFieldReference(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{name: "dot call", line: "spec.name", expected: true},
		{name: "spaced dot call", line: "spec . name", expected: true},
		{name: "safe navigation call", line: "spec&.name", expected: true},
		{name: "constant path call", line: "spec::name", expected: true},
		{name: "parenthesized receiver", line: "(spec).name", expected: true},
		{name: "reference in an expression", line: "enabled && spec.name", expected: true},
		{name: "receiver has a word prefix", line: "my_spec.name", expected: false},
		{name: "receiver has a word suffix", line: "specification.name", expected: false},
		{name: "field has a word suffix", line: "spec.name_suffix", expected: false},
		{name: "different field", line: "spec.version", expected: false},
		{name: "receiver without a call", line: "spec", expected: false},
		{name: "unrelated expression", line: "orders.name", expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, gemspecFieldReference(test.line, "spec", "name"))
		})
	}
}

func TestContinuedGemspecFieldReference(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		index    int
		expected bool
	}{
		{name: "first line", lines: []string{".name"}, index: 0, expected: false},
		{name: "only blank predecessors", lines: []string{"", ".name"}, index: 1, expected: false},
		{name: "unrelated predecessor", lines: []string{"other", ".name"}, index: 1, expected: false},
		{name: "dot on current line", lines: []string{"spec", ".name"}, index: 1, expected: true},
		{name: "safe navigation on current line", lines: []string{"spec", "&.name"}, index: 1, expected: true},
		{name: "dot on previous line", lines: []string{"spec.", "name"}, index: 1, expected: true},
		{name: "safe navigation on previous line", lines: []string{"spec&.", "name"}, index: 1, expected: true},
		{name: "explicit continuation after receiver", lines: []string{`spec \`, ".name"}, index: 1, expected: true},
		{name: "explicit continuation after dot", lines: []string{`spec. \`, "name"}, index: 1, expected: true},
		{name: "blank line between receiver and field", lines: []string{"spec", "", ".name"}, index: 2, expected: true},
		{name: "field has a word suffix", lines: []string{"spec", ".name_suffix"}, index: 1, expected: false},
		{name: "different field", lines: []string{"spec", ".version"}, index: 1, expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(
				t,
				test.expected,
				continuedGemspecFieldReference(test.lines, test.index, "spec", "name"),
			)
		})
	}
}

func TestConsumeRubyLiteral(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expected      string
		expectedRest  string
		expectedValid bool
	}{
		{name: "double quoted", value: `"orders"`, expected: "orders", expectedValid: true},
		{name: "single quoted", value: `'orders'`, expected: "orders", expectedValid: true},
		{name: "trailing input", value: `"orders", "1.2.3"`, expected: "orders", expectedRest: `, "1.2.3"`, expectedValid: true},
		{name: "frozen literal", value: `"orders".freeze`, expected: "orders", expectedValid: true},
		{name: "frozen literal with trailing input", value: `"orders".freeze, next`, expected: "orders", expectedRest: ", next", expectedValid: true},
		{name: "empty literal", value: `""`, expectedValid: true},
		{name: "empty input"},
		{name: "one byte input", value: `"`, expectedRest: `"`},
		{name: "non-string input", value: "Orders::NAME", expectedRest: "Orders::NAME"},
		{name: "unterminated literal", value: `"orders`, expectedRest: `"orders`},
		{name: "escaped literal", value: `"orders\\-api"`, expectedRest: `"orders\\-api"`},
		{name: "interpolated literal", value: `"orders#{suffix}"`, expectedRest: `"orders#{suffix}"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, rest, valid := consumeRubyLiteral(test.value)
			assert.Equal(t, test.expected, value)
			assert.Equal(t, test.expectedRest, rest)
			assert.Equal(t, test.expectedValid, valid)
		})
	}
}

func TestValidGemName(t *testing.T) {
	for _, name := range []string{
		"orders",
		"orders-api",
		"orders_api",
		"orders.api",
		"Orders2",
		"2orders",
		"a.",
	} {
		t.Run("accepts "+name, func(t *testing.T) {
			assert.True(t, validGemName(name))
		})
	}

	for _, name := range []string{
		"",
		"123",
		".orders",
		"-orders",
		"_orders",
		"orders service",
		"orders/api",
		"café",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			assert.False(t, validGemName(name))
		})
	}
}

func TestValidGemVersion(t *testing.T) {
	for _, version := range []string{
		"0",
		"1.2.3",
		"1.0.0.pre.1",
		"1.0.RC1",
		"1.0-rc.1",
		"1.0--rc",
	} {
		t.Run("accepts "+version, func(t *testing.T) {
			assert.True(t, validGemVersion(version))
		})
	}

	for _, version := range []string{
		"",
		"v1.0",
		".1",
		"1.",
		"1..0",
		"1_0",
		"1.0+build",
		"1 0",
	} {
		t.Run("rejects "+version, func(t *testing.T) {
			assert.False(t, validGemVersion(version))
		})
	}
}
