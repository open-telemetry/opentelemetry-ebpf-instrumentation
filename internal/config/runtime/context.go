// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime // import "go.opentelemetry.io/obi/internal/config/runtime"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

type protocolMetricSelectionKey struct{}

// WithProtocolMetricSelection enables protocol gating for span-derived metrics in a V2 run.
// V1 runs omit this selection to preserve their legacy exporter behavior.
func WithProtocolMetricSelection(ctx context.Context, selection instrumentations.InstrumentationSelection) context.Context {
	return context.WithValue(ctx, protocolMetricSelectionKey{}, selection)
}

func ProtocolMetricSelection(ctx context.Context) (instrumentations.InstrumentationSelection, bool) {
	selection, ok := ctx.Value(protocolMetricSelectionKey{}).(instrumentations.InstrumentationSelection)
	return selection, ok
}
