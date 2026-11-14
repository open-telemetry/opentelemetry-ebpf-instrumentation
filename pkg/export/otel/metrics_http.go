// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
)

func (mr *MetricsReporter) onHTTPServerRequests(deltas []request.HTTPServerRequestDelta) {
	if mr.httpActiveMetrics == nil {
		return
	}

	for i := range deltas {
		delta := &deltas[i]
		span := &delta.Span
		if delta.Delta == 0 || !span.Service.ExportModes.CanExportMetrics() || !span.Service.Features.HTTPServerActiveRequests() {
			continue
		}

		m := mr.httpActiveMetrics[span.Service.UID]
		if m == nil {
			if delta.Delta < 0 {
				continue
			}

			// Active requests must outlive the ordinary reporter cache's TTL and LRU eviction.
			metrics := mr.newMetricsInstance(&span.Service)
			meter := metrics.provider.Meter(reporterName, obiMeterOptions()...)
			counter, err := meter.Int64UpDownCounter(attributes.HTTPServerActiveRequests.OTEL,
				instrument.WithUnit(attributes.HTTPServerActiveRequests.Unit),
				instrument.WithDescription("Number of active HTTP server requests."))
			if err != nil {
				metrics.cancel()
				_ = metrics.provider.Shutdown(mr.ctx)
				mr.log.Error("creating HTTP active request metric", "error", err)
				continue
			}
			metrics.httpActiveRequests = counter
			m = &metrics
			mr.httpActiveMetrics[span.Service.UID] = m
		}

		attrs := make([]attribute.KeyValue, 0, len(mr.attrHTTPActiveRequests))
		for _, getter := range mr.attrHTTPActiveRequests {
			if kv := sanitizeKeyValue(getter.Get(span)); kv.Valid() {
				attrs = append(attrs, kv)
			}
		}
		m.httpActiveRequests.Add(m.ctx, delta.Delta, instrument.WithAttributes(attrs...))
		m.httpActiveCount += delta.Delta
		m.httpActiveUpdated = timeNow()
	}
}

func (mr *MetricsReporter) expireHTTPActiveRequests(ctx context.Context) {
	if mr.cfg.TTL <= 0 {
		return
	}
	for uid, m := range mr.httpActiveMetrics {
		if m.httpActiveCount != 0 || timeNow().Sub(m.httpActiveUpdated) <= mr.cfg.TTL {
			continue
		}
		m.cancel()
		if err := m.provider.Shutdown(ctx); err != nil {
			mr.log.Warn("expiring HTTP active request metrics", "error", err)
		}
		delete(mr.httpActiveMetrics, uid)
	}
}
