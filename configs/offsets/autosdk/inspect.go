// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	autosdk "go.opentelemetry.io/auto/sdk"
)

func main() {
	tracer := autosdk.TracerProvider().Tracer("offset-inspection")
	_, span := tracer.Start(context.Background(), "offset-inspection")
	span.End()
}
