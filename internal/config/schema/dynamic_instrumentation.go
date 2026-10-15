// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// DynamicSpanSpec declares a named span and its probe target.
type DynamicSpanSpec struct {
	Name                string                 `yaml:"name"`
	On                  DynamicSpanTarget      `yaml:"on"`
	Attributes          []DynamicSpanAttribute `yaml:"attributes,omitempty"`
	AutomaticAttributes bool                   `yaml:"automatic_attributes,omitempty"`
}

// DynamicSpanTarget is one of the shared function or USDT probe forms.
type DynamicSpanTarget struct {
	USDTNoRet      string            `yaml:"usdt_noret,omitempty"`
	USDTSpan       string            `yaml:"usdt,omitempty"`
	FunctionNoRet  string            `yaml:"function_noret,omitempty"`
	Function       string            `yaml:"function,omitempty"`
	Match          *DynamicSpanMatch `yaml:"match,omitempty"`
	targetKeyCount int
}

func (t *DynamicSpanTarget) UnmarshalYAML(node *yaml.Node) error {
	type plain DynamicSpanTarget
	var decoded plain
	if err := decodeKnownFields(node, &decoded); err != nil {
		return err
	}
	*t = DynamicSpanTarget(decoded)
	t.targetKeyCount = dynamicTargetKeyCount(node)
	return nil
}

func dynamicTargetKeyCount(node *yaml.Node) int {
	keys := map[string]struct{}{}
	collectDynamicTargetKeys(node, keys)
	return len(keys)
}

func collectDynamicTargetKeys(node *yaml.Node, keys map[string]struct{}) {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Value == "<<" {
			if value.Kind == yaml.SequenceNode {
				for _, merged := range value.Content {
					collectDynamicTargetKeys(merged, keys)
				}
			} else {
				collectDynamicTargetKeys(value, keys)
			}
			continue
		}
		switch key.Value {
		case "usdt_noret", "usdt", "function_noret", "function":
			keys[key.Value] = struct{}{}
		}
	}
}

func (t DynamicSpanTarget) validate(path string) error {
	targetCount := t.targetKeyCount
	if targetCount == 0 {
		for _, target := range []string{t.USDTNoRet, t.USDTSpan, t.FunctionNoRet, t.Function} {
			if target != "" {
				targetCount++
			}
		}
	}
	if targetCount != 1 {
		return fmt.Errorf("%s.on must define exactly one target", path)
	}
	if t.USDTNoRet == "" && t.USDTSpan == "" && t.FunctionNoRet == "" && t.Function == "" {
		return fmt.Errorf("%s.on target must not be empty", path)
	}
	if t.Match != nil && t.USDTNoRet == "" && t.USDTSpan == "" {
		return fmt.Errorf("%s.on.match is only supported for USDT targets", path)
	}
	if t.Match != nil {
		if err := validateArgumentIndex(t.Match.Argument.Index, path+".on.match.argument.index"); err != nil {
			return err
		}
	}
	return nil
}

func validateArgumentIndex(index *uint8, path string) error {
	if index == nil {
		return fmt.Errorf("%s is required", path)
	}
	if *index > 11 {
		return fmt.Errorf("%s must be between 0 and 11", path)
	}
	return nil
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

func (t DynamicArgumentType) valid() bool {
	switch t {
	case "", DynamicArgumentU8, DynamicArgumentU16, DynamicArgumentU32, DynamicArgumentU64,
		DynamicArgumentI8, DynamicArgumentI16, DynamicArgumentI32, DynamicArgumentI64, DynamicArgumentString:
		return true
	default:
		return false
	}
}

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
