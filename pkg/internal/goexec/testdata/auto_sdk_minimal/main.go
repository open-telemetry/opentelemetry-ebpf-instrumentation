// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"time"

	"go.opentelemetry.io/auto/sdk"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	now := time.Now()
	provider := sdk.TracerProvider()
	otel.SetTracerProvider(provider)
	_, span := otel.Tracer("test").Start(
		context.Background(),
		"test",
		trace.WithAttributes(attribute.String("test", "value")),
		trace.WithTimestamp(now),
	)
	span.End(trace.WithTimestamp(now.Add(time.Millisecond)))
}
