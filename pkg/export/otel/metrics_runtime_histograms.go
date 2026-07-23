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
	mu           sync.Mutex
	temporality  metricdata.Temporality
	histograms   map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState
	lastProduced map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState
}

type goRuntimeHistogramState struct {
	pid       app.PID
	time      time.Time
	startTime time.Time
	histogram runtimemetrics.GoRuntimeHistogramSnapshot
}

func newGoRuntimeHistogramProducer(temporality metricdata.Temporality) *goRuntimeHistogramProducer {
	return &goRuntimeHistogramProducer{
		temporality:  temporality,
		histograms:   make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, 2),
		lastProduced: make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, 2),
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

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	current := cloneGoRuntimeHistogramStates(p.histograms)
	states := current
	if p.temporality == metricdata.DeltaTemporality {
		states = deltaGoRuntimeHistogramStates(current, p.lastProduced)
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
		metric, err := produceGoRuntimeHistogram(kind, state, p.temporality)
		if err != nil {
			return nil, err
		}
		metrics = append(metrics, metric)
		delete(states, kind)
	}
	for kind := range states {
		return nil, fmt.Errorf("producing Go runtime histogram kind %d: unsupported kind", kind)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.temporality == metricdata.DeltaTemporality {
		p.lastProduced = current
	}

	return []metricdata.ScopeMetrics{{
		Scope:   instrumentation.Scope{Name: reporterName},
		Metrics: metrics,
	}}, nil
}

func cloneGoRuntimeHistogramStates(
	states map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState,
) map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState {
	cloned := make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, len(states))
	for kind, state := range states {
		state.histogram.Counts = append([]uint64(nil), state.histogram.Counts...)
		cloned[kind] = state
	}
	return cloned
}

func deltaGoRuntimeHistogramStates(
	current map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState,
	previous map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState,
) map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState {
	deltas := make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, len(current))
	for kind, state := range current {
		baseline, exists := previous[kind]
		if !exists ||
			baseline.pid != state.pid ||
			baseline.startTime != state.startTime ||
			histogramPopulationRegressed(baseline.histogram, state.histogram) {
			deltas[kind] = state
			continue
		}

		state.startTime = baseline.time
		state.histogram.Underflow -= baseline.histogram.Underflow
		state.histogram.Overflow -= baseline.histogram.Overflow
		// current's Counts must stay cumulative: it becomes the next baseline.
		counts := make([]uint64, len(state.histogram.Counts))
		var changed bool
		for i := range counts {
			counts[i] = state.histogram.Counts[i] - baseline.histogram.Counts[i]
			changed = changed || counts[i] != 0
		}
		state.histogram.Counts = counts
		if changed || state.histogram.Underflow != 0 || state.histogram.Overflow != 0 {
			deltas[kind] = state
		}
	}
	return deltas
}

func produceGoRuntimeHistogram(
	kind runtimemetrics.GoHistogramKind,
	state goRuntimeHistogramState,
	temporality metricdata.Temporality,
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
			Temporality: temporality,
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
