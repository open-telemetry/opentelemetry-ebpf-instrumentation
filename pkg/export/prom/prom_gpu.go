// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/gpuolly"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

type gpuMetric struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
	attrs     []attributes.Field[*gpuolly.Reading, string]
}

// gpuCollector reports the readings of the snapshot at each scrape.
type gpuCollector struct {
	snapshot *gpuolly.Snapshot
	metrics  map[attributes.Section]*gpuMetric
}

// ReportGPUMetrics exposes the readings of the snapshot in the Prometheus
// endpoint until ctx is done.
func ReportGPUMetrics(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	selectorCfg *attributes.SelectorConfig,
	snapshot *gpuolly.Snapshot,
) error {
	collector, err := newGPUCollector(ctxInfo.MetricAttributeGroups, selectorCfg, snapshot)
	if err != nil {
		return err
	}

	ctxInfo.Prometheus.Register(cfg.Port, cfg.Path, collector)
	go ctxInfo.Prometheus.StartHTTP(ctx)
	<-ctx.Done()

	return nil
}

func newGPUCollector(groups attributes.AttrGroups, selectorCfg *attributes.SelectorConfig, snapshot *gpuolly.Snapshot) (*gpuCollector, error) {
	provider, err := attributes.NewAttrSelector(groups, selectorCfg)
	if err != nil {
		return nil, fmt.Errorf("GPU Prometheus exporter attributes enable: %w", err)
	}

	collector := &gpuCollector{snapshot: snapshot, metrics: make(map[attributes.Section]*gpuMetric, len(gpuolly.Metrics))}
	for _, m := range gpuolly.Metrics {
		attrs := attributes.PrometheusGetters(gpuolly.StringGetters, provider.For(m.Name))

		valueType := prometheus.GaugeValue
		if m.Name.Type == attributes.InstrumentCounter {
			valueType = prometheus.CounterValue
		}

		collector.metrics[m.Name.Section] = &gpuMetric{
			desc:      prometheus.NewDesc(m.Name.Prom, m.Description, labelNames(attrs), nil),
			valueType: valueType,
			attrs:     attrs,
		}
	}

	return collector, nil
}

func (c *gpuCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.metrics {
		ch <- m.desc
	}
}

func (c *gpuCollector) Collect(ch chan<- prometheus.Metric) {
	labelsOf := func(r *gpuolly.Reading) []string {
		fields := c.metrics[r.Metric.Section].attrs
		labels := make([]string, 0, len(fields))
		for _, field := range fields {
			labels = append(labels, field.Get(r))
		}
		return labels
	}

	// A scrape must not contain the same series twice.
	key := func(r *gpuolly.Reading) string { return strings.Join(labelsOf(r), "\x00") }
	for _, point := range gpuolly.Group(c.snapshot.Load(), key) {
		m := c.metrics[point.Reading.Metric.Section]
		ch <- prometheus.MustNewConstMetric(m.desc, m.valueType, point.Value, labelsOf(point.Reading)...)
	}
}
