// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var tracer = otel.Tracer("trace-example")

func innerFunction(ctx context.Context) {
	_, span := tracer.Start(ctx, "child")
	defer span.End()
	span.SetAttributes(attribute.String("inner.key", "inner.value"))
}

func createMainSpan(ctx context.Context) {
	ctx, span := tracer.Start(ctx, "parent")

	defer span.End()

	innerFunction(ctx)

	intAttr := attribute.Int("int_key", 42)
	strAttr := attribute.String("string_key", "forty-two")
	boolAttr := attribute.Bool("bool_key", true)
	floatAttr := attribute.Float64("float_key", 42.3)
	span.SetAttributes(intAttr, strAttr, boolAttr, floatAttr)
}

func main() {
	createMainSpan(context.Background())
}
