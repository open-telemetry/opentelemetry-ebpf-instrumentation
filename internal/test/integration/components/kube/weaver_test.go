// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseExporterFailedCount(t *testing.T) {
	metrics := `# HELP otelcol_exporter_send_failed_metric_points Failed metric points.
# TYPE otelcol_exporter_send_failed_metric_points counter
otelcol_exporter_send_failed_metric_points{exporter="otlp/weaver"} 2
# TYPE otelcol_exporter_send_failed_spans counter
otelcol_exporter_send_failed_spans{exporter="otlp/weaver"} 3
# TYPE otelcol_exporter_enqueue_failed_spans counter
otelcol_exporter_enqueue_failed_spans{exporter="otlp/weaver"} 4
# TYPE otelcol_exporter_sent_spans counter
otelcol_exporter_sent_spans{exporter="otlp/weaver"} 100
`

	count, err := parseExporterFailedCount(strings.NewReader(metrics))
	require.NoError(t, err)
	require.InDelta(t, 9, count, 0)
}

func TestParseExporterFailedCountRejectsMalformedMetrics(t *testing.T) {
	_, err := parseExporterFailedCount(strings.NewReader("not prometheus text\n"))
	require.ErrorContains(t, err, "parsing exporter counters")
}
