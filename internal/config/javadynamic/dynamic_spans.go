// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javadynamic

import "fmt"

// V2SpanTarget is the Config v2 span target input needed to validate Java support.
type V2SpanTarget struct {
	Function            string
	FunctionNoRet       string
	USDTSpan            string
	USDTNoRet           string
	HasAttributes       bool
	AutomaticAttributes bool
}

// ValidateV2DynamicSpans validates the Java-supported subset of Config v2 spans.
func ValidateV2DynamicSpans(ruleIndex int, languageGlobs []string, languageRegex string, spans []V2SpanTarget) error {
	if len(spans) == 0 {
		return nil
	}
	path := fmt.Sprintf("capture.rules[%d].refine.spans", ruleIndex)
	if len(languageGlobs) != 1 || languageGlobs[0] != "java" || languageRegex != "" {
		return fmt.Errorf("%s is currently supported only for rules matching process.language_glob: [java]", path)
	}
	for spanIndex, span := range spans {
		spanPath := fmt.Sprintf("%s[%d]", path, spanIndex)
		if span.Function == "" || span.FunctionNoRet != "" || span.USDTSpan != "" || span.USDTNoRet != "" {
			return fmt.Errorf("%s.on.function is the only currently supported Java span target", spanPath)
		}
		if span.HasAttributes || span.AutomaticAttributes {
			return fmt.Errorf("%s.attributes and automatic_attributes are not currently supported", spanPath)
		}
		if _, err := ParseFunctionReference(span.Function); err != nil {
			return fmt.Errorf("%s.on.function: %w", spanPath, err)
		}
	}
	return nil
}
