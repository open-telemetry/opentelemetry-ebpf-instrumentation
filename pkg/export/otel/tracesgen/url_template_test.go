// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func httpClientSpan(subType int, route string) *request.Span {
	return &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: subType,
		Method:  "GET",
		Path:    "/users/42",
		Route:   route,
		Status:  200,
	}
}

func urlTemplateSelected(t *testing.T) map[attr.Name]struct{} {
	t.Helper()
	selected, err := UserSelectedAttributes(&attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{
			attributes.Traces.Section: attributes.InclusionLists{
				Include: []string{string(attr.HTTPUrlTemplate)},
			},
		},
	})
	require.NoError(t, err)
	return selected
}

func TestTraceAttributesSelector_URLTemplateOnHTTPClient(t *testing.T) {
	t.Run("not emitted by default", func(t *testing.T) {
		span := httpClientSpan(request.HTTPSubtypeNone, "/users/{id}")

		_, ok := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), "url.template")
		assert.False(t, ok)
	})

	t.Run("selected route matches the span name", func(t *testing.T) {
		span := httpClientSpan(request.HTTPSubtypeNone, "/users/{id}")

		v, ok := attrValue(TraceAttributesSelector(span, urlTemplateSelected(t)), "url.template")
		require.True(t, ok)
		assert.Equal(t, "/users/{id}", v.AsString())
		assert.Equal(t, "GET "+v.AsString(), span.TraceName())
	})

	t.Run("omitted without a route", func(t *testing.T) {
		span := httpClientSpan(request.HTTPSubtypeNone, "")

		_, ok := attrValue(TraceAttributesSelector(span, urlTemplateSelected(t)), "url.template")
		assert.False(t, ok)
		assert.Equal(t, "GET", span.TraceName())
	})

	t.Run("not on server spans", func(t *testing.T) {
		span := httpClientSpan(request.HTTPSubtypeNone, "/users/{id}")
		span.Type = request.EventTypeHTTP

		_, ok := attrValue(TraceAttributesSelector(span, urlTemplateSelected(t)), "url.template")
		assert.False(t, ok)
	})
}

func TestTraceAttributesSelector_URLTemplateFollowsTheRoute(t *testing.T) {
	for _, route := range []string{"/users/:id", "/users/*", "/users/42", "/**"} {
		t.Run(route, func(t *testing.T) {
			span := httpClientSpan(request.HTTPSubtypeNone, route)

			v, ok := attrValue(TraceAttributesSelector(span, urlTemplateSelected(t)), "url.template")
			require.True(t, ok)
			assert.Equal(t, route, v.AsString())
		})
	}
}

func TestTraceAttributesSelector_URLTemplateWithheldFromSubtypes(t *testing.T) {
	for name, span := range map[string]*request.Span{
		"elasticsearch": func() *request.Span {
			s := httpClientSpan(request.HTTPSubtypeElasticsearch, "/users/{id}")
			s.Elasticsearch = &request.Elasticsearch{DBOperationName: "search", DBCollectionName: "users"}
			return s
		}(),
		"sql++":    httpClientSpan(request.HTTPSubtypeSQLPP, "users"),
		"json-rpc": httpClientSpan(request.HTTPSubtypeJSONRPC, "/users/{id}"),
		"aws s3": func() *request.Span {
			s := httpClientSpan(request.HTTPSubtypeAWSS3, "/users/{id}")
			s.AWS = &request.AWS{S3: request.AWSS3{Method: "GetObject"}}
			return s
		}(),
		"openai": func() *request.Span {
			s := httpClientSpan(request.HTTPSubtypeOpenAI, "/users/{id}")
			s.GenAI = &request.GenAI{OpenAI: &request.VendorOpenAI{}}
			return s
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := attrValue(TraceAttributesSelector(span, urlTemplateSelected(t)), "url.template")
			assert.False(t, ok)
		})
	}
}
