// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"go.opentelemetry.io/obi/internal/config/dynamicspan"
	"go.opentelemetry.io/obi/internal/config/schema"
)

func validateV2DynamicSpans(ruleIndex int, rule schema.Rule) error {
	spans := make([]dynamicspan.V2SpanTarget, 0, len(rule.Refine.Spans))
	for _, span := range rule.Refine.Spans {
		spans = append(spans, dynamicspan.V2SpanTarget{
			Function:            span.On.Function,
			FunctionNoRet:       span.On.FunctionNoRet,
			USDTSpan:            span.On.USDTSpan,
			USDTNoRet:           span.On.USDTNoRet,
			HasAttributes:       len(span.Attributes) != 0,
			AutomaticAttributes: span.AutomaticAttributes,
		})
	}
	return dynamicspan.ValidateV2(ruleIndex, spans)
}
