// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
)

type SamplerName string

const (
	SamplerAlwaysOn                SamplerName = "always_on"
	SamplerAlwaysOff               SamplerName = "always_off"
	SamplerTraceIDRatio            SamplerName = "traceidratio"
	SamplerParentBasedAlwaysOn     SamplerName = "parentbased_always_on"
	SamplerParentBasedAlwaysOff    SamplerName = "parentbased_always_off"
	SamplerParentBasedTraceIDRatio SamplerName = "parentbased_traceidratio"
	SamplerOBIRuleBased            SamplerName = "obi_rule_based"
)

type SamplerLeafConfig struct {
	Name SamplerName `yaml:"name"`
	Arg  string      `yaml:"arg"`
}

type OBIRuleBasedSamplerMatch struct {
	ResourceAttributes map[string]string `yaml:"resource_attributes"`
}

type OBIRuleBasedSamplerRule struct {
	Match  OBIRuleBasedSamplerMatch `yaml:"match"`
	Action SamplerLeafConfig        `yaml:"action"`
}

type OBIRuleBasedSamplerConfig struct {
	Fallback SamplerLeafConfig         `yaml:"fallback"`
	Rules    []OBIRuleBasedSamplerRule `yaml:"rules"`
}

// Sampler standard configuration
// https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler
// We don't support, yet, the jaeger and xray samplers.
type SamplerConfig struct {
	Name         SamplerName                `yaml:"name" env:"OTEL_TRACES_SAMPLER" validate:"omitempty,oneof=always_on always_off traceidratio parentbased_always_on parentbased_always_off parentbased_traceidratio obi_rule_based"`
	Arg          string                     `yaml:"arg" env:"OTEL_TRACES_SAMPLER_ARG"`
	OBIRuleBased *OBIRuleBasedSamplerConfig `yaml:"obi_rule_based,omitempty"`
}

func (s *SamplerConfig) Implementation() trace.Sampler {
	defaultSampler := func() trace.Sampler {
		return trace.ParentBased(trace.AlwaysSample())
	}

	if s == nil {
		return defaultSampler()
	}

	if s.OBIRuleBased != nil {
		return s.OBIRuleBased.Implementation()
	}

	log := slog.With("component", "otel.Sampler", "name", s.Name, "arg", s.Arg)
	return builtinSamplerImplementation(s.Name, s.Arg, log, defaultSampler)
}

func (s SamplerLeafConfig) Implementation() trace.Sampler {
	defaultSampler := func() trace.Sampler {
		return trace.ParentBased(trace.AlwaysSample())
	}
	log := slog.With("component", "otel.Sampler", "name", s.Name, "arg", s.Arg)
	return builtinSamplerImplementation(s.Name, s.Arg, log, defaultSampler)
}

func builtinSamplerImplementation(name SamplerName, arg string, log *slog.Logger, defaultSampler func() trace.Sampler) trace.Sampler {
	switch name {
	case SamplerAlwaysOn:
		return trace.AlwaysSample()
	case SamplerAlwaysOff:
		return trace.NeverSample()
	case SamplerTraceIDRatio:
		ratio, err := strconv.ParseFloat(arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.TraceIDRatioBased(ratio)
	case SamplerParentBasedAlwaysOff:
		return trace.ParentBased(trace.NeverSample())
	case SamplerParentBasedTraceIDRatio:
		ratio, err := strconv.ParseFloat(arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.ParentBased(trace.TraceIDRatioBased(ratio))
	case SamplerParentBasedAlwaysOn, "":
		return defaultSampler()
	default:
		log.Warn("unsupported sampler name. Defaulting to parentbased_always_on")
		return defaultSampler()
	}
}

func (c *OBIRuleBasedSamplerConfig) Implementation() trace.Sampler {
	fallback := c.Fallback.Implementation()
	rules := make([]obiRuleBasedSamplerRule, 0, len(c.Rules))
	for _, rule := range c.Rules {
		rules = append(rules, obiRuleBasedSamplerRule{
			resourceAttributes: rule.Match.ResourceAttributes,
			action:             rule.Action.Implementation(),
		})
	}
	return &obiRuleBasedSampler{fallback: fallback, rules: rules}
}

type obiRuleBasedSampler struct {
	fallback trace.Sampler
	rules    []obiRuleBasedSamplerRule
}

type obiRuleBasedSamplerRule struct {
	resourceAttributes map[string]string
	action             trace.Sampler
}

func (s *obiRuleBasedSampler) ShouldSample(params trace.SamplingParameters) trace.SamplingResult {
	attrs := map[string]string{}
	for _, attr := range params.Attributes {
		attrs[string(attr.Key)] = samplingAttributeString(attr.Value)
	}

	for _, rule := range s.rules {
		if rule.matches(attrs) {
			return rule.action.ShouldSample(params)
		}
	}

	return s.fallback.ShouldSample(params)
}

func (s *obiRuleBasedSampler) Description() string {
	return "obi_rule_based"
}

func (r obiRuleBasedSamplerRule) matches(attrs map[string]string) bool {
	for key, want := range r.resourceAttributes {
		got, ok := attrs[key]
		if !ok || got != want {
			return false
		}
	}

	return true
}

func samplingAttributeString(v attribute.Value) string {
	switch v.Type() {
	case attribute.STRING:
		return v.AsString()
	case attribute.BOOL:
		return strconv.FormatBool(v.AsBool())
	case attribute.INT64:
		return strconv.FormatInt(v.AsInt64(), 10)
	case attribute.FLOAT64:
		return strconv.FormatFloat(v.AsFloat64(), 'f', -1, 64)
	case attribute.STRINGSLICE:
		return strings.Join(v.AsStringSlice(), ",")
	case attribute.BOOLSLICE:
		return fmt.Sprint(v.AsBoolSlice())
	case attribute.INT64SLICE:
		return fmt.Sprint(v.AsInt64Slice())
	case attribute.FLOAT64SLICE:
		return fmt.Sprint(v.AsFloat64Slice())
	default:
		return fmt.Sprint(v.AsInterface())
	}
}
