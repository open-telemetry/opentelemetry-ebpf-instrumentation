// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"go.opentelemetry.io/auto/sdk"
)

func main() {
	tracer := sdk.TracerProvider().Tracer("test")
	_, span := tracer.Start(context.Background(), "test")
	span.End()
}
