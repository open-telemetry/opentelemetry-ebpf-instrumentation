// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dynamicspan

import "fmt"

// V2SpanTarget is the Config v2 span target input needed to validate supported spans.
type V2SpanTarget struct {
	Function            string
	FunctionNoRet       string
	USDTSpan            string
	USDTNoRet           string
	HasAttributes       bool
	AutomaticAttributes bool
}

// ValidateV2 validates the currently supported subset of Config v2 spans.
func ValidateV2(ruleIndex int, spans []V2SpanTarget) error {
	if len(spans) == 0 {
		return nil
	}
	path := fmt.Sprintf("capture.rules[%d].refine.spans", ruleIndex)
	for spanIndex, span := range spans {
		spanPath := fmt.Sprintf("%s[%d]", path, spanIndex)
		if span.Function == "" || span.FunctionNoRet != "" || span.USDTSpan != "" || span.USDTNoRet != "" {
			return fmt.Errorf("%s.on.function is the only currently supported Java span target", spanPath)
		}
		if span.HasAttributes || span.AutomaticAttributes {
			return fmt.Errorf("%s.attributes and automatic_attributes are not currently supported", spanPath)
		}
	}
	return nil
}
