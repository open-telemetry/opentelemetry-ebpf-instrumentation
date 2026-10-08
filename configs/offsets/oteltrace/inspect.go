// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/trace"
)

func main() {
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
	})

	fmt.Println(spanContext)
	_, span := trace.SpanFromContext(context.Background()).TracerProvider().Tracer("offsets").Start(context.Background(), "inspect")
	fmt.Println(span.SpanContext())
	span.End()
}
