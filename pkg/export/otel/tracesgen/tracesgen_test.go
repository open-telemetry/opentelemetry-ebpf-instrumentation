// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestTraceAttributesSelector_DNSQuestionName(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeDNS,
		Method: "A",
		Path:   "example.com",
	}

	defaultAttrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})
	assert.NotEmpty(t, defaultAttrs)
	assert.NotContains(t, defaultAttrs, semconv.DNSQuestionName("example.com"))

	selectedAttrs, err := UserSelectedAttributes(&attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{
			"traces": attributes.InclusionLists{
				Include: []string{"dns.question.name"},
			},
		},
	})
	require.NoError(t, err)
	assert.Contains(t, selectedAttrs, attr.DNSQuestionName)

	optInAttrs := TraceAttributesSelector(span, selectedAttrs)
	assert.Contains(t, optInAttrs, semconv.DNSQuestionName("example.com"))
}
