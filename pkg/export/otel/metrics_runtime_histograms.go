// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type goRuntimeHistogramProducer struct {
	mu         sync.RWMutex
	histograms map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState
}

type goRuntimeHistogramState struct {
	pid       app.PID
	time      time.Time
	startTime time.Time
	histogram runtimemetrics.GoRuntimeHistogramSnapshot
}

func newGoRuntimeHistogramProducer() *goRuntimeHistogramProducer {
	return &goRuntimeHistogramProducer{
		histograms: make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, 2),
	}
}

func (p *goRuntimeHistogramProducer) Update(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if snapshot.Histogram == nil {
		return
	}

	histogram := *snapshot.Histogram
	histogram.Counts = append([]uint64(nil), snapshot.Histogram.Counts...)
	name, err := goRuntimeHistogramMetricName(histogram.Kind)
	if err != nil {
		rmlog().Warn("skipping unsupported Go runtime histogram",
			"pid", snapshot.PID,
			"kind", histogram.Kind,
			"error", err)
		return
	}
	if _, err := histogram.Data(); err != nil {
		rmlog().Warn("skipping malformed Go runtime histogram",
			"pid", snapshot.PID,
			"metric", name,
			"error", err)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	previous, exists := p.histograms[histogram.Kind]
	startTime := previous.startTime
	if !exists || previous.pid != snapshot.PID || histogramPopulationRegressed(previous.histogram, histogram) {
		startTime = snapshot.Time
	}
	p.histograms[histogram.Kind] = goRuntimeHistogramState{
		pid:       snapshot.PID,
		time:      snapshot.Time,
		startTime: startTime,
		histogram: histogram,
	}
}

func histogramPopulationRegressed(
	previous runtimemetrics.GoRuntimeHistogramSnapshot,
	current runtimemetrics.GoRuntimeHistogramSnapshot,
) bool {
	if previous.Underflow > current.Underflow || previous.Overflow > current.Overflow ||
		len(previous.Counts) != len(current.Counts) {
		return true
	}
	for i, population := range previous.Counts {
		if population > current.Counts[i] {
			return true
		}
	}
	return false
}

func (p *goRuntimeHistogramProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.RLock()
	states := make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, len(p.histograms))
	for kind, state := range p.histograms {
		state.histogram.Counts = append([]uint64(nil), state.histogram.Counts...)
		states[kind] = state
	}
	p.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(states) == 0 {
		return nil, nil
	}

	metrics := make([]metricdata.Metrics, 0, len(states))
	for _, kind := range []runtimemetrics.GoHistogramKind{
		runtimemetrics.GoHistogramKindGCPause,
		runtimemetrics.GoHistogramKindSchedLatency,
	} {
		state, ok := states[kind]
		if !ok {
			continue
		}
		metric, err := produceGoRuntimeHistogram(kind, state)
		if err != nil {
			return nil, err
		}
		metrics = append(metrics, metric)
		delete(states, kind)
	}
	for kind := range states {
		return nil, fmt.Errorf("producing Go runtime histogram kind %d: unsupported kind", kind)
	}

	return []metricdata.ScopeMetrics{{
		Scope:   instrumentation.Scope{Name: reporterName},
		Metrics: metrics,
	}}, nil
}

func produceGoRuntimeHistogram(
	kind runtimemetrics.GoHistogramKind,
	state goRuntimeHistogramState,
) (metricdata.Metrics, error) {
	name, err := goRuntimeHistogramMetricName(kind)
	if err != nil {
		return metricdata.Metrics{}, err
	}
	data, err := state.histogram.Data()
	if err != nil {
		return metricdata.Metrics{}, fmt.Errorf("converting %s histogram: %w", name, err)
	}

	return metricdata.Metrics{
		Name: name,
		Unit: "s",
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints: []metricdata.HistogramDataPoint[float64]{
				{
					StartTime:    state.startTime,
					Time:         state.time,
					Count:        data.Count,
					Bounds:       data.Bounds,
					BucketCounts: data.BucketCounts,
					Sum:          data.Sum,
				},
			},
		},
	}, nil
}

func goRuntimeHistogramMetricName(kind runtimemetrics.GoHistogramKind) (string, error) {
	switch kind {
	case runtimemetrics.GoHistogramKindGCPause:
		return attributes.GoRuntimeMemoryGCPauseDuration.OTEL, nil
	case runtimemetrics.GoHistogramKindSchedLatency:
		return attributes.GoRuntimeScheduleDuration.OTEL, nil
	default:
		return "", fmt.Errorf("producing Go runtime histogram kind %d: unsupported kind", kind)
	}
}
