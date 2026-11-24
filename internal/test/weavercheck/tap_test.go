// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const tapTelemetry = `# HELP otelcol_exporter_send_failed_metric_points Failed metric points.
# TYPE otelcol_exporter_send_failed_metric_points counter
otelcol_exporter_send_failed_metric_points{exporter="otlp/weaver"} 2
otelcol_exporter_send_failed_metric_points{exporter="otlp/jaeger"} 7
# TYPE otelcol_exporter_send_failed_spans counter
otelcol_exporter_send_failed_spans{exporter="otlp/weaver"} 3
# TYPE otelcol_exporter_enqueue_failed_spans counter
otelcol_exporter_enqueue_failed_spans{exporter="otlp/weaver"} 4
# TYPE otelcol_exporter_sent_spans counter
otelcol_exporter_sent_spans{exporter="otlp/weaver"} 100
# TYPE otelcol_exporter_queue_size gauge
otelcol_exporter_queue_size{data_type="metrics",exporter="otlp/weaver"} 5
otelcol_exporter_queue_size{data_type="traces",exporter="otlp/weaver"} 1
otelcol_exporter_queue_size{data_type="traces",exporter="otlp/jaeger"} 8
# TYPE otelcol_exporter_sent_metric_points counter
otelcol_exporter_sent_metric_points{exporter="otlp/weaver",server_address="weaver",server_port="4317"} 20
otelcol_exporter_sent_metric_points{exporter="otlp/jaeger"} 50
# TYPE otelcol_receiver_accepted_metric_points counter
otelcol_receiver_accepted_metric_points{receiver="otlp",transport="grpc"} 30
otelcol_receiver_accepted_metric_points{receiver="otlp/apps",transport="http"} 40
# TYPE otelcol_receiver_accepted_spans counter
otelcol_receiver_accepted_spans{receiver="otlp",transport="http"} 6
`

func TestParseTapStatsAllExporters(t *testing.T) {
	stats, err := ParseTapStats(strings.NewReader(tapTelemetry), AllExporters)
	require.NoError(t, err)
	require.InDelta(t, 16, stats.Failed, 0)
	require.InDelta(t, 14, stats.Queued, 0)
}

func TestParseTapStatsOneExporter(t *testing.T) {
	stats, err := ParseTapStats(strings.NewReader(tapTelemetry), "otlp/weaver")
	require.NoError(t, err)
	require.InDelta(t, 9, stats.Failed, 0)
	require.Equal(t, map[string]float64{"metric_points": 2, "spans": 7}, stats.FailedBySignal)
	require.InDelta(t, 6, stats.Queued, 0)
}

func TestParseTapStatsCountsDeliveredAndReceivedItems(t *testing.T) {
	stats, err := ParseTapStats(strings.NewReader(tapTelemetry), "otlp/weaver")
	require.NoError(t, err)
	require.Equal(t, map[string]float64{"spans": 100, "metric_points": 20}, stats.Sent)
	require.Equal(t, map[string]float64{"spans": 6, "metric_points": 30}, stats.Received, "only what OBI sends to the tap receiver counts")
}

func TestParseTapStatsReportsWhetherTheExporterIsPresent(t *testing.T) {
	stats, err := ParseTapStats(strings.NewReader(tapTelemetry), "otlp/weaver")
	require.NoError(t, err)
	require.True(t, stats.Found)

	stats, err = ParseTapStats(strings.NewReader(tapTelemetry), "otlp/lgtm")
	require.NoError(t, err)
	require.False(t, stats.Found)
	require.Zero(t, stats.Failed)
	require.Zero(t, stats.Queued)
}

func TestTapStatsSettled(t *testing.T) {
	empty := TapStats{Found: true}
	queued := TapStats{Found: true, Queued: 2}

	require.True(t, empty.Settled(empty))
	require.False(t, queued.Settled(empty), "items still queued")
	require.False(t, empty.Settled(queued), "the queue emptied only since the last scrape")
}

func TestParseTapStatsRejectsMalformedMetrics(t *testing.T) {
	_, err := ParseTapStats(strings.NewReader("not prometheus text\n"), AllExporters)
	require.ErrorContains(t, err, "parsing exporter counters")
}

func TestParseTapStatsKeepsUnsentConfiguredSignals(t *testing.T) {
	for dataType, signal := range map[string]string{
		"metrics": "metric_points", "traces": "spans", "logs": "log_records", "profiles": "profile_samples",
	} {
		t.Run(dataType, func(t *testing.T) {
			telemetry := fmt.Sprintf(`# TYPE otelcol_exporter_queue_capacity gauge
otelcol_exporter_queue_capacity{exporter="otlp/weaver",data_type="%s"} 500
# TYPE otelcol_receiver_accepted_%s_total counter
otelcol_receiver_accepted_%s_total{receiver="otlp"} 1
`, dataType, signal, signal)
			stats, err := ParseTapStats(strings.NewReader(telemetry), weaverTapExporter)
			require.NoError(t, err)
			require.Empty(t, stats.Sent)
			require.Equal(t, map[string]float64{signal: 1}, stats.Received)
		})
	}
}

func TestParseTapStatsScopesSignalsWithoutQueueTelemetry(t *testing.T) {
	telemetry := `# TYPE otelcol_exporter_sent_log_records_total counter
otelcol_exporter_sent_log_records_total{exporter="otlp/weaver"} 0
# TYPE otelcol_receiver_accepted_log_records_total counter
otelcol_receiver_accepted_log_records_total{receiver="otlp"} 1
# TYPE otelcol_receiver_accepted_spans_total counter
otelcol_receiver_accepted_spans_total{receiver="otlp"} 2
`
	stats, err := ParseTapStats(strings.NewReader(telemetry), weaverTapExporter)
	require.NoError(t, err)
	require.Equal(t, map[string]float64{"log_records": 0}, stats.Sent)
	require.Equal(t, map[string]float64{"log_records": 1}, stats.Received)
}

func TestParseTapStatsScopesFailedSignalsWithoutQueueTelemetry(t *testing.T) {
	telemetry := `# TYPE otelcol_exporter_send_failed_log_records_total counter
otelcol_exporter_send_failed_log_records_total{exporter="otlp/weaver"} 1
# TYPE otelcol_receiver_accepted_log_records_total counter
otelcol_receiver_accepted_log_records_total{receiver="otlp"} 1
# TYPE otelcol_receiver_accepted_spans_total counter
otelcol_receiver_accepted_spans_total{receiver="otlp"} 2
`
	stats, err := ParseTapStats(strings.NewReader(telemetry), weaverTapExporter)
	require.NoError(t, err)
	require.Empty(t, stats.Sent)
	require.Equal(t, map[string]float64{"log_records": 1}, stats.FailedBySignal)
	require.Equal(t, map[string]float64{"log_records": 1}, stats.Received)
}
