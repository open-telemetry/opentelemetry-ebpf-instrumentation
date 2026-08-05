// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestSpansForTraceExport(t *testing.T) {
	input := []request.Span{
		{Type: request.EventTypeHTTP, Method: "undecided"},
		{
			Type:        request.EventTypeHTTP,
			Method:      "sampled",
			TraceFlags:  uint8(trace.FlagsSampled | trace.FlagsRandom),
			BPFDecision: true,
		},
		{
			Type:        request.EventTypeHTTP,
			Method:      "unsampled",
			TraceFlags:  uint8(trace.FlagsRandom),
			BPFDecision: true,
		},
	}
	original := append([]request.Span(nil), input...)

	output := spansForTraceExport(input)

	assert.Equal(t, []request.Span{input[0], input[1]}, output)
	assert.Equal(t, original, input)
}
