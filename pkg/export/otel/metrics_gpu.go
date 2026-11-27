// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/gpuolly"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

const gpuScopeName = "gpu_devices"

type gpuInstrument struct {
	observable metric2.Float64Observable
	attrs      []attributes.Field[*gpuolly.Reading, attribute.KeyValue]
}

// ReportGPUMetrics exports the readings of the snapshot, each time the
// metrics are collected, until ctx is done.
func ReportGPUMetrics(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	snapshot *gpuolly.Snapshot,
) (retErr error) {
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("instantiating the GPU metrics exporter: %w", err)
	}
	defer releaseExporterOnError(ctx, exporter, &retErr)

	provider := metric.NewMeterProvider(
		metric.WithResource(createFilteredStatsResource(ctxInfo.NodeMeta.HostID, selectorCfg.SelectionCfg)),
		metric.WithReader(metric.NewPeriodicReader(instrumentMetricsExporter(ctxInfo.Metrics, exporter), metric.WithInterval(cfg.Interval))),
	)

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, selectorCfg)
	if err != nil {
		return fmt.Errorf("GPU OTEL exporter attributes enable: %w", err)
	}

	if err := observeGPUMetrics(provider.Meter(gpuScopeName, obiMeterOptions()...), attrProv, snapshot); err != nil {
		return err
	}

	<-ctx.Done()

	shutdownCtx, cancel := shutdownContext(ctx)
	defer cancel()

	if err := provider.Shutdown(shutdownCtx); err != nil {
		slog.Warn("error shutting down GPU metrics provider", "component", "otel.GPUMetricsExporter", "error", err)
	}

	return nil
}

// observeGPUMetrics registers the GPU instruments, which report the readings
// of the snapshot each time the metrics are collected.
func observeGPUMetrics(meter metric2.Meter, attrProv *attributes.AttrSelector, snapshot *gpuolly.Snapshot) error {
	instruments := make(map[attributes.Section]*gpuInstrument, len(gpuolly.Metrics))
	observables := make([]metric2.Observable, 0, len(gpuolly.Metrics))
	for _, m := range gpuolly.Metrics {
		observable, err := newGPUObservable(meter, m)
		if err != nil {
			return fmt.Errorf("creating the %s instrument: %w", m.Name.OTEL, err)
		}

		instruments[m.Name.Section] = &gpuInstrument{
			observable: observable,
			attrs:      attributes.OpenTelemetryGetters(gpuolly.Getters, attrProv.For(m.Name)),
		}
		observables = append(observables, observable)
	}

	attrsOf := func(r *gpuolly.Reading) attribute.Set {
		fields := instruments[r.Metric.Section].attrs
		keyValues := make([]attribute.KeyValue, 0, len(fields))
		for _, field := range fields {
			keyValues = append(keyValues, field.Get(r))
		}
		return attribute.NewSet(keyValues...)
	}

	observe := func(_ context.Context, observer metric2.Observer) error {
		key := func(r *gpuolly.Reading) attribute.Distinct {
			attrs := attrsOf(r)
			return attrs.Equivalent()
		}
		for _, point := range gpuolly.Group(snapshot.Load(), key) {
			observable := instruments[point.Reading.Metric.Section].observable
			observer.ObserveFloat64(observable, point.Value, metric2.WithAttributeSet(attrsOf(point.Reading)))
		}
		return nil
	}

	if _, err := meter.RegisterCallback(observe, observables...); err != nil {
		return fmt.Errorf("registering the GPU metrics callback: %w", err)
	}

	return nil
}

func newGPUObservable(meter metric2.Meter, m gpuolly.Metric) (metric2.Float64Observable, error) {
	unit, description := metric2.WithUnit(m.Name.Unit), metric2.WithDescription(m.Description)

	switch m.Name.Type {
	case attributes.InstrumentCounter:
		return meter.Float64ObservableCounter(m.Name.OTEL, unit, description)
	case attributes.InstrumentUpDownCounter:
		return meter.Float64ObservableUpDownCounter(m.Name.OTEL, unit, description)
	default:
		return meter.Float64ObservableGauge(m.Name.OTEL, unit, description)
	}
}
