// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

func init() {
	externalTracer = func(context.Context) trace.Tracer {
		return otel.Tracer("go-auto-sdk-activation-test",
			trace.WithInstrumentationVersion("v1.0.0"),
			trace.WithSchemaURL("https://opentelemetry.io/schemas/1.30.0"))
	}
}
