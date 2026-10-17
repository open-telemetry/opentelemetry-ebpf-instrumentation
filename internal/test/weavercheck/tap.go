// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck // import "go.opentelemetry.io/obi/internal/test/weavercheck"

import (
	"fmt"
	"io"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

const AllExporters = ""

const (
	exporterMetricPrefix        = "otelcol_exporter_"
	exporterFailedSendPrefix    = "otelcol_exporter_send_failed_"
	exporterFailedEnqueuePrefix = "otelcol_exporter_enqueue_failed_"
	exporterQueueSize           = "otelcol_exporter_queue_size"
	exporterLabel               = "exporter"
)

type exporterMetricKind int

const (
	notExporterMetric exporterMetricKind = iota
	otherExporterMetric
	failedExporterMetric
	queueExporterMetric
)

type TapStats struct {
	Found  bool
	Failed float64
	Queued float64
}

func (s TapStats) Settled(previous TapStats) bool {
	return s.Queued == 0 && previous.Queued == 0
}

func ParseTapStats(reader io.Reader, exporter string) (TapStats, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(reader)
	if err != nil {
		return TapStats{}, fmt.Errorf("parsing exporter counters: %w", err)
	}

	var stats TapStats
	for name, family := range families {
		kind := exporterMetricKindOf(name)
		if kind == notExporterMetric {
			continue
		}

		for _, metric := range family.Metric {
			if !exporterMatches(metric.GetLabel(), exporter) {
				continue
			}
			stats.Found = true
			if err := stats.add(kind, name, metric); err != nil {
				return TapStats{}, err
			}
		}
	}
	return stats, nil
}

func exporterMetricKindOf(name string) exporterMetricKind {
	switch {
	case !strings.HasPrefix(name, exporterMetricPrefix):
		return notExporterMetric
	case strings.HasPrefix(name, exporterFailedSendPrefix), strings.HasPrefix(name, exporterFailedEnqueuePrefix):
		return failedExporterMetric
	case name == exporterQueueSize:
		return queueExporterMetric
	default:
		return otherExporterMetric
	}
}

func (s *TapStats) add(kind exporterMetricKind, name string, metric *dto.Metric) error {
	switch kind {
	case failedExporterMetric:
		if metric.Counter == nil {
			return fmt.Errorf("exporter failure metric %s is not a counter", name)
		}
		s.Failed += metric.Counter.GetValue()
	case queueExporterMetric:
		if metric.Gauge == nil {
			return fmt.Errorf("exporter queue metric %s is not a gauge", name)
		}
		s.Queued += metric.Gauge.GetValue()
	}
	return nil
}

func exporterMatches(labels []*dto.LabelPair, exporter string) bool {
	if exporter == AllExporters {
		return true
	}

	for _, label := range labels {
		if label.GetName() == exporterLabel {
			return label.GetValue() == exporter
		}
	}
	return false
}
