// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/obi/pkg/activerequests"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

type activeRequestSeriesKey struct {
	service svc.UID
	attrs   attribute.Distinct
}

type activeRequestSeries struct {
	service   svc.Attrs
	attrs     attribute.Set
	startTime time.Time
	lastSeen  time.Time
	lastValue int64
}

type activeRequestOTLPState struct {
	series         map[activeRequestSeriesKey]*activeRequestSeries
	lastCollection time.Time
}

func (mr *MetricsReporter) activeRequestsEnabled(ctxInfo *global.ContextInfo) bool {
	return mr.jointMetricsCfg.Features.HTTPServerActiveRequests() && mr.is.HTTPEnabled() &&
		ctxInfo.AppO11y.ActiveRequestsConfig != nil && ctxInfo.AppO11y.EBPFEventContext != nil
}

func (mr *MetricsReporter) setupActiveRequestsMetrics() {
	mr.activeRequestsProvider = metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(
			sharedExporter{newActiveRequestsExporter(mr)},
			metric.WithInterval(mr.cfg.Interval),
		)),
	)
}

// activeRequestsExporter reads active requests at each periodic export.
type activeRequestsExporter struct {
	sdkmetric.Exporter
	reporter *MetricsReporter
	state    activeRequestOTLPState
}

func newActiveRequestsExporter(mr *MetricsReporter) sdkmetric.Exporter {
	return &activeRequestsExporter{
		Exporter: mr.exporter,
		reporter: mr,
		state: activeRequestOTLPState{
			series: map[activeRequestSeriesKey]*activeRequestSeries{},
		},
	}
}

func (e *activeRequestsExporter) Export(ctx context.Context, _ *metricdata.ResourceMetrics) error {
	counts, err := e.reporter.activeRequestsReader.Collect(e.reporter.activeRequestAttrs)
	if err != nil {
		return fmt.Errorf("collecting active HTTP requests: %w", err)
	}

	var errs []error
	for _, metrics := range e.state.resourceMetrics(e.reporter, counts, timeNow()) {
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		if err := e.Exporter.Export(ctx, &metrics); err != nil {
			errs = append(errs, fmt.Errorf("exporting active HTTP requests: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (s *activeRequestOTLPState) resourceMetrics(
	mr *MetricsReporter, counts []activerequests.Count, now time.Time,
) []metricdata.ResourceMetrics {
	current := make(map[activeRequestSeriesKey]int64, len(counts))
	for _, count := range counts {
		key := activeRequestSeriesKey{service: count.Service.UID, attrs: count.Attributes.Equivalent()}
		current[key] += count.Value
		series, ok := s.series[key]
		if !ok {
			series = &activeRequestSeries{startTime: now}
			s.series[key] = series
		}
		series.service = count.Service
		series.attrs = count.Attributes
		series.lastSeen = now
	}

	type serviceMetrics struct {
		service svc.Attrs
		points  []metricdata.DataPoint[int64]
	}
	byService := map[svc.UID]*serviceMetrics{}
	temporality := mr.exporter.Temporality(sdkmetric.InstrumentKindObservableUpDownCounter)
	for key, series := range s.series {
		value, active := current[key]
		previous := series.lastValue
		if !active && previous == 0 && mr.cfg.TTL > 0 && now.Sub(series.lastSeen) > mr.cfg.TTL {
			delete(s.series, key)
			continue
		}
		series.lastValue = value

		startTime := series.startTime
		if temporality == metricdata.DeltaTemporality {
			if !s.lastCollection.IsZero() {
				startTime = s.lastCollection
			}
			value -= previous
		}

		group := byService[key.service]
		if group == nil {
			group = &serviceMetrics{service: series.service}
			byService[key.service] = group
		}
		group.points = append(group.points, metricdata.DataPoint[int64]{
			Attributes: series.attrs,
			StartTime:  startTime,
			Time:       now,
			Value:      value,
		})
	}
	s.lastCollection = now

	result := make([]metricdata.ResourceMetrics, 0, len(byService))
	for _, group := range byService {
		resourceAttributes := append(otelcfg.GetAppResourceAttrs(&mr.nodeMeta, &group.service),
			otelcfg.ResourceAttrsFromEnv(&group.service)...)
		resourceAttributes = otelcfg.FilterResourceAttrs(resourceAttributes, mr.userAttribSelection)
		result = append(result, metricdata.ResourceMetrics{
			Resource: resource.NewWithAttributes(attr.OBISchemaURL, resourceAttributes...),
			ScopeMetrics: []metricdata.ScopeMetrics{{
				Scope: instrumentation.Scope{
					Name:      reporterName,
					Version:   attr.TelemetryDistroVersion(),
					SchemaURL: attr.OBISchemaURL,
				},
				Metrics: []metricdata.Metrics{{
					Name: attributes.HTTPServerActiveRequests.OTEL,
					Unit: attributes.HTTPServerActiveRequests.Unit,
					Data: metricdata.Sum[int64]{
						DataPoints:  group.points,
						Temporality: temporality,
					},
				}},
			}},
		})
	}
	return result
}
