// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type goRuntimeHistogramCollector struct {
	gcPauseDesc        *prometheus.Desc
	scheduleDesc       *prometheus.Desc
	mu                 sync.RWMutex
	histogramSnapshots map[goRuntimeHistogramKey]goRuntimeHistogramState
}

type goRuntimeHistogramKey struct {
	kind       runtimemetrics.GoHistogramKind
	labelTuple string
}

type goRuntimeHistogramState struct {
	labels    []string
	histogram runtimemetrics.GoRuntimeHistogramSnapshot
}

func newGoRuntimeHistogramCollector(runtimeLabelNames []string) *goRuntimeHistogramCollector {
	return &goRuntimeHistogramCollector{
		gcPauseDesc: prometheus.NewDesc(
			attributes.GoRuntimeMemoryGCPauseDuration.Prom,
			"Duration of stop-the-world Go garbage collection pauses.",
			runtimeLabelNames,
			nil,
		),
		scheduleDesc: prometheus.NewDesc(
			attributes.GoRuntimeScheduleDuration.Prom,
			"Time goroutines spend runnable before being scheduled to run.",
			runtimeLabelNames,
			nil,
		),
		histogramSnapshots: make(map[goRuntimeHistogramKey]goRuntimeHistogramState),
	}
}

func (c *goRuntimeHistogramCollector) Update(
	labels []string,
	histogram *runtimemetrics.GoRuntimeHistogramSnapshot,
) {
	if c == nil || histogram == nil {
		return
	}

	state := goRuntimeHistogramState{
		labels: append([]string(nil), labels...),
		histogram: runtimemetrics.GoRuntimeHistogramSnapshot{
			Kind:      histogram.Kind,
			Counts:    append([]uint64(nil), histogram.Counts...),
			Underflow: histogram.Underflow,
			Overflow:  histogram.Overflow,
		},
	}
	key := goRuntimeHistogramKey{
		kind:       histogram.Kind,
		labelTuple: runtimeHistogramLabelTuple(labels),
	}

	c.mu.Lock()
	c.histogramSnapshots[key] = state
	c.mu.Unlock()
}

func (c *goRuntimeHistogramCollector) Delete(labels []string) {
	if c == nil {
		return
	}

	labelTuple := runtimeHistogramLabelTuple(labels)
	c.mu.Lock()
	for key := range c.histogramSnapshots {
		if key.labelTuple == labelTuple {
			delete(c.histogramSnapshots, key)
		}
	}
	c.mu.Unlock()
}

func (c *goRuntimeHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.gcPauseDesc
	ch <- c.scheduleDesc
}

func (c *goRuntimeHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	states := c.snapshot()
	for _, state := range states {
		desc, ok := c.descriptor(state.histogram.Kind)
		if !ok {
			mlog().Warn("skipping unsupported Go runtime histogram", "kind", state.histogram.Kind)
			continue
		}

		data, err := state.histogram.Data()
		if err != nil {
			mlog().Warn("skipping malformed Go runtime histogram", "kind", state.histogram.Kind, "error", err)
			continue
		}
		if len(data.BucketCounts) != len(data.Bounds)+1 {
			mlog().Warn(
				"skipping malformed Go runtime histogram",
				"kind", state.histogram.Kind,
				"bucket_counts", len(data.BucketCounts),
				"bounds", len(data.Bounds),
			)
			continue
		}

		buckets := make(map[float64]uint64, len(data.Bounds))
		var cumulative uint64
		for i, upperBound := range data.Bounds {
			cumulative += data.BucketCounts[i]
			buckets[upperBound] = cumulative
		}
		metric, err := prometheus.NewConstHistogram(
			desc,
			data.Count,
			data.Sum,
			buckets,
			state.labels...,
		)
		if err != nil {
			mlog().Warn("skipping malformed Go runtime histogram", "kind", state.histogram.Kind, "error", err)
			continue
		}
		ch <- metric
	}
}

func (c *goRuntimeHistogramCollector) snapshot() []goRuntimeHistogramState {
	c.mu.RLock()
	states := make([]goRuntimeHistogramState, 0, len(c.histogramSnapshots))
	for _, state := range c.histogramSnapshots {
		states = append(states, goRuntimeHistogramState{
			labels: append([]string(nil), state.labels...),
			histogram: runtimemetrics.GoRuntimeHistogramSnapshot{
				Kind:      state.histogram.Kind,
				Counts:    append([]uint64(nil), state.histogram.Counts...),
				Underflow: state.histogram.Underflow,
				Overflow:  state.histogram.Overflow,
			},
		})
	}
	c.mu.RUnlock()
	return states
}

func (c *goRuntimeHistogramCollector) descriptor(
	kind runtimemetrics.GoHistogramKind,
) (*prometheus.Desc, bool) {
	switch kind {
	case runtimemetrics.GoHistogramKindGCPause:
		return c.gcPauseDesc, true
	case runtimemetrics.GoHistogramKindSchedLatency:
		return c.scheduleDesc, true
	default:
		return nil, false
	}
}

func runtimeHistogramLabelTuple(labels []string) string {
	key := make([]byte, 0, len(labels)*8)
	for _, label := range labels {
		key = strconv.AppendInt(key, int64(len(label)), 10)
		key = append(key, ':')
		key = append(key, label...)
	}
	return string(key)
}
