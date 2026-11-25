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
	exporterSentPrefix          = "otelcol_exporter_sent_"
	exporterQueueSize           = "otelcol_exporter_queue_size"
	exporterLabel               = "exporter"
	exporterDataTypeLabel       = "data_type"
	receiverAcceptedPrefix      = "otelcol_receiver_accepted_"
	receiverLabel               = "receiver"
	// the receiver OBI exports to in every collector that taps weaver
	tapReceiver = "otlp"
)

type exporterMetricKind int

const (
	notExporterMetric exporterMetricKind = iota
	otherExporterMetric
	failedExporterMetric
	sentExporterMetric
	queueExporterMetric
)

type TapStats struct {
	Found          bool
	Failed         float64
	Queued         float64
	FailedBySignal map[string]float64
	Sent           map[string]float64
	Received       map[string]float64
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

	stats := TapStats{
		FailedBySignal: make(map[string]float64),
		Sent:           make(map[string]float64),
		Received:       make(map[string]float64),
	}
	tapSignals := make(map[string]bool)
	for name, family := range families {
		if strings.HasPrefix(name, receiverAcceptedPrefix) {
			if err := stats.addReceived(name, family.Metric); err != nil {
				return TapStats{}, err
			}
			continue
		}

		kind := exporterMetricKindOf(name)
		if kind == notExporterMetric {
			continue
		}

		for _, metric := range family.Metric {
			if !exporterMatches(metric.GetLabel(), exporter) {
				continue
			}
			stats.Found = true
			if signal := exporterSignal(metric.GetLabel()); signal != "" {
				tapSignals[signal] = true
			}
			if err := stats.add(kind, name, metric); err != nil {
				return TapStats{}, err
			}
		}
	}
	// The receiver can also feed pipelines that do not export to this tap.
	if len(tapSignals) > 0 || len(stats.Sent) > 0 || len(stats.FailedBySignal) > 0 {
		for signal := range stats.Received {
			_, sent := stats.Sent[signal]
			_, failed := stats.FailedBySignal[signal]
			if !sent && !failed && !tapSignals[signal] {
				delete(stats.Received, signal)
			}
		}
	}
	return stats, nil
}

func exporterSignal(labels []*dto.LabelPair) string {
	for _, label := range labels {
		if label.GetName() != exporterDataTypeLabel {
			continue
		}
		switch label.GetValue() {
		case "metrics":
			return "metric_points"
		case "traces":
			return "spans"
		case "logs":
			return "log_records"
		case "profiles":
			return "profile_samples"
		}
	}
	return ""
}

func exporterMetricKindOf(name string) exporterMetricKind {
	switch {
	case !strings.HasPrefix(name, exporterMetricPrefix):
		return notExporterMetric
	case strings.HasPrefix(name, exporterFailedSendPrefix), strings.HasPrefix(name, exporterFailedEnqueuePrefix):
		return failedExporterMetric
	case strings.HasPrefix(name, exporterSentPrefix):
		return sentExporterMetric
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
		signal, found := strings.CutPrefix(name, exporterFailedSendPrefix)
		if !found {
			signal = strings.TrimPrefix(name, exporterFailedEnqueuePrefix)
		}
		signal = strings.TrimSuffix(signal, "_total")
		s.FailedBySignal[signal] += metric.Counter.GetValue()
	case sentExporterMetric:
		if metric.Counter == nil {
			return fmt.Errorf("exporter sent metric %s is not a counter", name)
		}
		signal := strings.TrimSuffix(strings.TrimPrefix(name, exporterSentPrefix), "_total")
		s.Sent[signal] += metric.Counter.GetValue()
	case queueExporterMetric:
		if metric.Gauge == nil {
			return fmt.Errorf("exporter queue metric %s is not a gauge", name)
		}
		s.Queued += metric.Gauge.GetValue()
	}
	return nil
}

func (s *TapStats) addReceived(name string, metrics []*dto.Metric) error {
	for _, metric := range metrics {
		if !labelEquals(metric.GetLabel(), receiverLabel, tapReceiver) {
			continue
		}
		if metric.Counter == nil {
			return fmt.Errorf("receiver metric %s is not a counter", name)
		}
		signal := strings.TrimSuffix(strings.TrimPrefix(name, receiverAcceptedPrefix), "_total")
		s.Received[signal] += metric.Counter.GetValue()
	}
	return nil
}

func labelEquals(labels []*dto.LabelPair, name, value string) bool {
	for _, label := range labels {
		if label.GetName() == name {
			return label.GetValue() == value
		}
	}
	return false
}

func exporterMatches(labels []*dto.LabelPair, exporter string) bool {
	return exporter == AllExporters || labelEquals(labels, exporterLabel, exporter)
}
