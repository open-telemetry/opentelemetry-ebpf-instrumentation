// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/embedded"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
)

func TestCleanupAllMetricsInstances_RemovesGenAIOutputTokenUsage(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	inputMetric := newTestFloat64Histogram()
	outputMetric := newTestFloat64Histogram()

	metrics := &Metrics{
		ctx:                   ctx,
		genAIInputTokenUsage:  newTestExpirer(ctx, inputMetric, "input"),
		genAIOutputTokenUsage: newTestExpirer(ctx, outputMetric, "output"),
	}

	metrics.cleanupAllMetricsInstances()

	assert.Equal(t, []attribute.Set{testAttributeSet("input")}, inputMetric.removed())
	assert.Equal(t, []attribute.Set{testAttributeSet("output")}, outputMetric.removed())
	assert.Empty(t, metrics.genAIInputTokenUsage.entries.All())
	assert.Empty(t, metrics.genAIOutputTokenUsage.entries.All())
}

type testFloat64Histogram struct {
	embedded.Float64Histogram

	mu           sync.Mutex
	removedAttrs []attribute.Set
}

func newTestFloat64Histogram() *testFloat64Histogram {
	return &testFloat64Histogram{}
}

func (h *testFloat64Histogram) Record(context.Context, float64, ...instrument.RecordOption) {}

func (h *testFloat64Histogram) Remove(_ context.Context, options ...instrument.RemoveOption) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.removedAttrs = append(h.removedAttrs, instrument.NewRemoveConfig(options).Attributes())
}

func (h *testFloat64Histogram) removed() []attribute.Set {
	h.mu.Lock()
	defer h.mu.Unlock()

	removed := make([]attribute.Set, len(h.removedAttrs))
	copy(removed, h.removedAttrs)
	return removed
}

func newTestExpirer(
	ctx context.Context,
	metric instrument.Float64Histogram,
	value string,
) *Expirer[*request.Span, instrument.Float64Histogram, float64] {
	expirer := NewExpirer[*request.Span, instrument.Float64Histogram, float64](
		ctx,
		metric,
		[]attributes.Field[*request.Span, attribute.KeyValue]{
			{
				ExposedName: "token.type",
				Get: func(*request.Span) attribute.KeyValue {
					return attribute.String("token.type", value)
				},
			},
		},
		time.Now,
		time.Minute,
	)

	expirer.ForRecord(&request.Span{})

	return expirer
}

func testAttributeSet(value string) attribute.Set {
	return attribute.NewSet(attribute.String("token.type", value))
}
