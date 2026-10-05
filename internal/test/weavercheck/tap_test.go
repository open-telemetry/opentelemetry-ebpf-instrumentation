// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
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
	require.InDelta(t, 6, stats.Queued, 0)
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
