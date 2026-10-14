// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// DynamicInstrumentation declares shared, language-neutral dynamic
// instrumentation rules. Parsing this section does not apply the rules.
type DynamicInstrumentation struct {
	Rules []DynamicInstrumentationRule `yaml:"rules,omitempty"`
}

func (d *DynamicInstrumentation) Validate() error {
	if d == nil {
		return nil
	}
	if len(d.Rules) == 0 {
		return errors.New("dynamic_instrumentation.rules must not be empty")
	}
	for i, rule := range d.Rules {
		if len(rule.Service) == 0 {
			return fmt.Errorf("dynamic_instrumentation.rules[%d].service must not be empty", i)
		}
		if len(rule.Spans) == 0 {
			return fmt.Errorf("dynamic_instrumentation.rules[%d].spans must not be empty", i)
		}
		for j, span := range rule.Spans {
			if span.Name == "" {
				return fmt.Errorf("dynamic_instrumentation.rules[%d].spans[%d].name must not be empty", i, j)
			}
			if err := span.On.validate(i, j); err != nil {
				return err
			}
			if span.On.Match != nil && span.On.Match.Value == "" {
				return fmt.Errorf("dynamic_instrumentation.rules[%d].spans[%d].on.match.value must not be empty", i, j)
			}
			for k, attr := range span.Attributes {
				if attr.Name == "" {
					return fmt.Errorf("dynamic_instrumentation.rules[%d].spans[%d].attributes[%d].name must not be empty", i, j, k)
				}
				if err := validateArgumentIndex(attr.Argument.Index, fmt.Sprintf("dynamic_instrumentation.rules[%d].spans[%d].attributes[%d].argument.index", i, j, k)); err != nil {
					return err
				}
				if !attr.Argument.Type.valid() {
					return fmt.Errorf("dynamic_instrumentation.rules[%d].spans[%d].attributes[%d].argument.type %q is not supported", i, j, k, attr.Argument.Type)
				}
			}
		}
	}
	return nil
}

// DynamicInstrumentationRule selects services and names the spans to add.
type DynamicInstrumentationRule struct {
	Service services.GlobDefinitionCriteria `yaml:"service"`
	Spans   []DynamicSpanSpec               `yaml:"spans"`
}

func (r DynamicInstrumentationRule) MarshalYAML() (any, error) {
	service := make([]dynamicServiceSelector, len(r.Service))
	for i, selector := range r.Service {
		languages, err := globSelectorString(selector.Languages)
		if err != nil {
			return nil, err
		}
		path, err := globSelectorString(selector.Path)
		if err != nil {
			return nil, err
		}
		cmdArgs, err := globSelectorString(selector.CmdArgs)
		if err != nil {
			return nil, err
		}
		service[i] = dynamicServiceSelector{
			Name:           selector.Name,
			Namespace:      selector.Namespace,
			OpenPorts:      selector.OpenPorts,
			Languages:      languages,
			PIDs:           selector.PIDs,
			Path:           path,
			CmdArgs:        cmdArgs,
			Metadata:       selector.Metadata,
			PodLabels:      selector.PodLabels,
			PodAnnotations: selector.PodAnnotations,
			ContainersOnly: selector.ContainersOnly,
		}
	}
	return struct {
		Service []dynamicServiceSelector `yaml:"service"`
		Spans   []DynamicSpanSpec        `yaml:"spans"`
	}{Service: service, Spans: r.Spans}, nil
}

func globSelectorString(value services.GlobAttr) (string, error) {
	encoded, err := value.MarshalYAML()
	if err != nil {
		return "", err
	}
	pattern, ok := encoded.(string)
	if !ok {
		return "", fmt.Errorf("marshaled service glob must be a string, got %T", encoded)
	}
	return pattern, nil
}

type dynamicServiceSelector struct {
	Name           string                        `yaml:"name,omitempty"`
	Namespace      string                        `yaml:"namespace,omitempty"`
	OpenPorts      services.IntEnum              `yaml:"open_ports,omitempty"`
	Languages      string                        `yaml:"languages,omitempty"`
	PIDs           []uint32                      `yaml:"target_pids,omitempty"`
	Path           string                        `yaml:"exe_path,omitempty"`
	CmdArgs        string                        `yaml:"cmd_args,omitempty"`
	Metadata       services.MetadataGlobMap      `yaml:",inline"`
	PodLabels      map[string]*services.GlobAttr `yaml:"k8s_pod_labels,omitempty"`
	PodAnnotations map[string]*services.GlobAttr `yaml:"k8s_pod_annotations,omitempty"`
	ContainersOnly bool                          `yaml:"containers_only,omitempty"`
}

// DynamicSpanSpec declares a named span and its probe target.
type DynamicSpanSpec struct {
	Name       string                 `yaml:"name"`
	On         DynamicSpanTarget      `yaml:"on"`
	Attributes []DynamicSpanAttribute `yaml:"attributes,omitempty"`
}

// DynamicSpanTarget is one of the shared function or USDT probe forms.
type DynamicSpanTarget struct {
	USDTNoRet      string            `yaml:"usdt_noret,omitempty"`
	USDTSpan       string            `yaml:"usdt_span,omitempty"`
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
	t.targetKeyCount = 0
	for i := 0; i < len(node.Content)-1; i += 2 {
		switch node.Content[i].Value {
		case "usdt_noret", "usdt_span", "function_noret", "function":
			t.targetKeyCount++
		}
	}
	return nil
}

func (t DynamicSpanTarget) validate(ruleIndex, spanIndex int) error {
	targetCount := t.targetKeyCount
	if targetCount == 0 {
		for _, target := range []string{t.USDTNoRet, t.USDTSpan, t.FunctionNoRet, t.Function} {
			if target != "" {
				targetCount++
			}
		}
	}
	if targetCount != 1 {
		return fmt.Errorf("dynamic_instrumentation.rules[%d].spans[%d].on must define exactly one target", ruleIndex, spanIndex)
	}
	if t.USDTNoRet == "" && t.USDTSpan == "" && t.FunctionNoRet == "" && t.Function == "" {
		return fmt.Errorf("dynamic_instrumentation.rules[%d].spans[%d].on target must not be empty", ruleIndex, spanIndex)
	}
	if t.Match != nil && t.USDTNoRet == "" && t.USDTSpan == "" {
		return fmt.Errorf("dynamic_instrumentation.rules[%d].spans[%d].on.match is only supported for USDT targets", ruleIndex, spanIndex)
	}
	if t.Match != nil {
		if err := validateArgumentIndex(t.Match.Argument.Index, fmt.Sprintf("dynamic_instrumentation.rules[%d].spans[%d].on.match.argument.index", ruleIndex, spanIndex)); err != nil {
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
