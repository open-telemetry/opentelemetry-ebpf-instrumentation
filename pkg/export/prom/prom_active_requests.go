// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/activerequests"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
)

type activeRequestsCollector struct {
	source *activerequests.Reader
	desc   *prometheus.Desc
	attrs  []attr.Name
	ttl    time.Duration
	clock  func() time.Time
	mu     sync.Mutex
	series map[string]activeRequestsPromSeries
}

type activeRequestsPromSeries struct {
	labels   []string
	count    float64
	lastSeen time.Time
}

func newActiveRequestsCollector(
	source *activerequests.Reader,
	attrs []attr.Name,
	ttl time.Duration,
) *activeRequestsCollector {
	labels := make([]string, len(attrs))
	for i, name := range attrs {
		labels[i] = name.Prom()
	}
	return &activeRequestsCollector{
		source: source,
		desc: prometheus.NewDesc(
			attributes.HTTPServerActiveRequests.Prom,
			"Number of HTTP server requests currently being handled.",
			labels,
			nil,
		),
		attrs:  attrs,
		ttl:    ttl,
		clock:  timeNow,
		series: map[string]activeRequestsPromSeries{},
	}
}

func (r *metricsReporter) activeRequestsEnabled(jointMetricsConfig *perapp.GlobalMetricsConfig) bool {
	return jointMetricsConfig.Features.HTTPServerActiveRequests() && r.is.HTTPEnabled() &&
		r.ctxInfo.AppO11y.ActiveRequestsConfig != nil && r.ctxInfo.AppO11y.EBPFEventContext != nil
}

func (r *metricsReporter) setupActiveRequestsCollector(attrsProvider *attributes.AttrSelector) {
	reader := activerequests.NewReader(r.ctxInfo.AppO11y.EBPFEventContext, *r.ctxInfo.AppO11y.ActiveRequestsConfig)
	attrs := attrsProvider.For(attributes.HTTPServerActiveRequests)
	r.activeRequests = newActiveRequestsCollector(reader, attrs, r.cfg.TTL)
}

func (c *activeRequestsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *activeRequestsCollector) Collect(ch chan<- prometheus.Metric) {
	counts, err := c.source.Collect(c.attrs)
	if err != nil {
		mlog().Warn("collecting active HTTP requests failed", "error", err)
		return
	}
	for _, metric := range c.collectCounts(counts) {
		ch <- metric
	}
}

func (c *activeRequestsCollector) collectCounts(activeCounts []activerequests.Count) []prometheus.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()

	counts := make(map[string]activeRequestsPromSeries, len(activeCounts))
	for _, active := range activeCounts {
		labels := make([]string, len(c.attrs))
		for i, name := range c.attrs {
			if value, ok := active.Attributes.Value(name.OTEL()); ok {
				labels[i] = value.Emit()
			}
		}
		key := expire.LabelsKey(labels)
		if current, ok := counts[key]; ok {
			current.count += float64(active.Value)
			counts[key] = current
			continue
		}
		counts[key] = activeRequestsPromSeries{labels: labels, count: float64(active.Value)}
	}

	now := c.clock()
	for key, previous := range c.series {
		if current, ok := counts[key]; ok {
			current.lastSeen = now
			c.series[key] = current
			delete(counts, key)
		} else if c.ttl > 0 && now.Sub(previous.lastSeen) > c.ttl {
			delete(c.series, key)
		} else {
			previous.count = 0
			c.series[key] = previous
		}
	}
	for key, current := range counts {
		current.lastSeen = now
		c.series[key] = current
	}
	toEmit := make([]prometheus.Metric, 0, len(c.series))
	for _, current := range c.series {
		toEmit = append(toEmit, prometheus.MustNewConstMetric(
			c.desc,
			prometheus.GaugeValue,
			current.count,
			current.labels...,
		))
	}
	return toEmit
}
