// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
	})

	fmt.Println(trace.ContextWithRemoteSpanContext(context.Background(), spanContext))
	fmt.Println(
		trace.WithAttributes(attribute.String("test", "value")),
		trace.WithTimestamp(time.Unix(0, 1)),
	)
	_, recordingSpan := sdktrace.NewTracerProvider().
		Tracer("test").
		Start(context.Background(), "recording")
	fmt.Println(recordingSpan.SpanContext())
	recordingSpan.End()
}
