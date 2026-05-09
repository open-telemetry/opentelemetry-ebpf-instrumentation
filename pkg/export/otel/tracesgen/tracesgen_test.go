// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

func TestTraceAttributesSelector_DNSQuestionName(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeDNS,
		Method: "A",
		Path:   "example.com",
	}

	// When optionalAttrs is empty, DNSQuestionName is not emitted
	emptyAttrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})
	assert.NotEmpty(t, emptyAttrs)
	assert.NotContains(t, emptyAttrs, semconv.DNSQuestionName("example.com"))

	// With default config (no explicit user selection), DNSQuestionName defaults
	// to true for traces, so it should be present in the selected attributes.
	defaultAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)
	assert.Contains(t, defaultAttrs, attr.DNSQuestionName)

	optInAttrs := TraceAttributesSelector(span, defaultAttrs)
	assert.Contains(t, optInAttrs, semconv.DNSQuestionName("example.com"))
}

func TestGenAIToolCallAttributes(t *testing.T) {
	t.Run("nil tool calls", func(t *testing.T) {
		assert.Nil(t, genAIToolCallAttributes(nil))
	})

	t.Run("empty tool calls", func(t *testing.T) {
		assert.Nil(t, genAIToolCallAttributes([]request.ToolCall{}))
	})

	t.Run("single tool call with ID", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{ID: "call_1", Name: "get_weather"},
		})
		require.Len(t, attrs, 2)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_weather"}), attrs[0])
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolCallID), []string{"call_1"}), attrs[1])
	})

	t.Run("multiple tool calls with IDs", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{ID: "call_1", Name: "get_weather"},
			{ID: "call_2", Name: "get_time"},
		})
		require.Len(t, attrs, 2)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_weather", "get_time"}), attrs[0])
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolCallID), []string{"call_1", "call_2"}), attrs[1])
	})

	t.Run("tool calls without IDs", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{Name: "get_weather"},
			{Name: "get_time"},
		})
		require.Len(t, attrs, 1)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_weather", "get_time"}), attrs[0])
	})

	t.Run("skips empty names", func(t *testing.T) {
		attrs := genAIToolCallAttributes([]request.ToolCall{
			{ID: "call_1", Name: ""},
			{ID: "call_2", Name: "get_time"},
		})
		require.Len(t, attrs, 2)
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolName), []string{"get_time"}), attrs[0])
		assert.Equal(t, attribute.StringSlice(string(attr.GenAIToolCallID), []string{"call_2"}), attrs[1])
	})
}

func TestGroupSpansUsesResourceAttrsForSampling(t *testing.T) {
	span := request.Span{
		Type:   request.EventTypeHTTP,
		Method: "GET",
		Path:   "/orders",
		Service: svc.Attrs{
			UID: svc.UID{
				Name:      "frontend",
				Namespace: "default",
			},
		},
		TraceID: oteltrace.TraceID{1},
	}

	resourceSampler := samplerFunc(func(params trace.SamplingParameters) trace.SamplingResult {
		for _, kv := range params.Attributes {
			if kv.Key == "service.name" && kv.Value.AsString() == "frontend" {
				return trace.SamplingResult{Decision: trace.RecordAndSample}
			}
		}
		return trace.SamplingResult{Decision: trace.Drop}
	})

	noResourceGroups := GroupSpans(
		context.Background(),
		[]request.Span{span},
		map[attr.Name]struct{}{},
		resourceSampler,
		nil,
		instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{instrumentations.InstrumentationALL}),
	)
	assert.Empty(t, noResourceGroups)

	withResourceGroups := GroupSpans(
		context.Background(),
		[]request.Span{span},
		map[attr.Name]struct{}{},
		resourceSampler,
		func(service *svc.Attrs) []attribute.KeyValue {
			return []attribute.KeyValue{
				attribute.String("service.name", service.UID.Name),
				attribute.String("service.namespace", service.UID.Namespace),
			}
		},
		instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{instrumentations.InstrumentationALL}),
	)
	assert.Len(t, withResourceGroups, 1)
	assert.Len(t, withResourceGroups[span.Service.UID], 1)
}

type samplerFunc func(params trace.SamplingParameters) trace.SamplingResult

func (f samplerFunc) ShouldSample(params trace.SamplingParameters) trace.SamplingResult {
	return f(params)
}

func (samplerFunc) Description() string {
	return "test"
}
