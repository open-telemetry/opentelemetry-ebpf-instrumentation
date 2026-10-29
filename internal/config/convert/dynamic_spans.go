// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	nodejsconfig "go.opentelemetry.io/obi/internal/config/nodejs"
	"go.opentelemetry.io/obi/internal/config/schema"
)

func validateV2DynamicSpans(ruleIndex int, rule schema.Rule) error {
	spans := make([]nodejsconfig.V2SpanTarget, 0, len(rule.Refine.Spans))
	for _, span := range rule.Refine.Spans {
		spans = append(spans, nodejsconfig.V2SpanTarget{
			Function:            span.On.Function,
			FunctionNoRet:       span.On.FunctionNoRet,
			USDTSpan:            span.On.USDTSpan,
			USDTNoRet:           span.On.USDTNoRet,
			HasAttributes:       len(span.Attributes) != 0,
			AutomaticAttributes: span.AutomaticAttributes,
		})
	}
	return nodejsconfig.ValidateV2DynamicSpans(
		ruleIndex,
		rule.Match.Process.LanguageGlob,
		rule.Match.Process.LanguageRegex,
		spans,
	)
}
