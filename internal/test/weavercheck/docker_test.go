// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseDockerPS(t *testing.T) {
	out := strings.Join([]string{
		"aaa\tdocker.io/otel/opentelemetry-collector-contrib@sha256:abc\tsuite_default\t",
		"bbb\totel/opentelemetry-collector-contrib:0.161.0\thost\thttp://127.0.0.1:18888/metrics",
		"ccc\totel/weaver:v0.26.1\tsuite_default,other\t",
		"malformed line",
	}, "\n") + "\n"

	require.Equal(t, []runningContainer{
		{id: "aaa", image: "otel/opentelemetry-collector-contrib@sha256:abc", networks: []string{"suite_default"}, telemetryURL: defaultCollectorTelemetryURL},
		{id: "bbb", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"host"}, telemetryURL: "http://127.0.0.1:18888/metrics"},
		{id: "ccc", image: "otel/weaver:v0.26.1", networks: []string{"suite_default", "other"}, telemetryURL: defaultCollectorTelemetryURL},
	}, parseDockerPS(out))
}

func TestWithoutRegistryHost(t *testing.T) {
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("docker.io/otel/weaver:v0.26.1"))
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("localhost/otel/weaver:v0.26.1"))
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("registry.local:5000/otel/weaver:v0.26.1"))
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("otel/weaver:v0.26.1"))
	require.Equal(t, "prometheus/prometheus:v3", withoutRegistryHost("quay.io/prometheus/prometheus:v3"))
}

func TestCollectorsBesideWeaverKeepsOnlyCollectorsSharingANetwork(t *testing.T) {
	weaver := runningContainer{id: "weaver", image: "otel/weaver:v0.26.1", networks: []string{"suite_default"}}
	tap := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"suite_default"}}
	stale := runningContainer{id: "stale", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"old_run"}}
	other := runningContainer{id: "prometheus", image: "quay.io/prometheus/prometheus:v3", networks: []string{"suite_default"}}

	require.Equal(t, []runningContainer{tap}, collectorsBesideWeaver([]runningContainer{weaver, tap, stale, other}))
}

func TestCollectorsBesideWeaverOnHostNetworking(t *testing.T) {
	weaver := runningContainer{id: "weaver", image: "otel/weaver:v0.26.1", networks: []string{"host"}}
	tap := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"host"}}

	require.Equal(t, []runningContainer{tap}, collectorsBesideWeaver([]runningContainer{weaver, tap}))
}

func TestCollectorsBesideWeaverWithoutWeaver(t *testing.T) {
	collector := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"suite_default"}}

	require.Empty(t, collectorsBesideWeaver([]runningContainer{collector}))
}

func TestWeaverRunning(t *testing.T) {
	weaver := runningContainer{id: "weaver", image: "otel/weaver:v0.26.1", networks: []string{"suite_default"}}
	collector := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"suite_default"}}

	require.True(t, weaverRunning([]runningContainer{collector, weaver}))
	require.False(t, weaverRunning([]runningContainer{collector}))
	require.False(t, weaverRunning(nil))
}

func TestDependencyImageFindsTheScraperImage(t *testing.T) {
	image, err := dependencyImage(busyboxDependencyStage)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(image, "busybox:"), image)
	require.Contains(t, image, "@sha256:")
}

func TestDependencyImageInIgnoresOtherStages(t *testing.T) {
	dockerfile := "FROM golang:1.26 AS builder\nFROM busybox:musl@sha256:abc AS busybox-musl\n"

	image, ok := dependencyImageIn(dockerfile, "busybox-musl")
	require.True(t, ok)
	require.Equal(t, "busybox:musl@sha256:abc", image)

	_, ok = dependencyImageIn(dockerfile, "missing")
	require.False(t, ok)
}

func TestDrainWaitsForEachSignal(t *testing.T) {
	tests := []struct {
		name   string
		sample func(time.Duration) string
		want   time.Duration
	}{
		{
			name: "traces do not bypass a ten second metric interval",
			sample: func(elapsed time.Duration) string {
				if elapsed >= 10*time.Second {
					return drainTelemetry(10000, 10000, 100, 1)
				}
				return drainTelemetry(float64(elapsed/time.Millisecond), float64(elapsed/time.Millisecond), 100, 0)
			},
			want: 10*time.Second + dockerTapPoll,
		},
		{
			name: "metric queue is known before the first sent counter",
			sample: func(elapsed time.Duration) string {
				if elapsed >= 10*time.Second {
					return drainTelemetry(10000, 10000, 100, 1)
				}
				out := drainTelemetry(float64(elapsed/time.Millisecond), float64(elapsed/time.Millisecond), 100, 0)
				out = strings.ReplaceAll(out, "# TYPE otelcol_exporter_sent_metric_points_total counter\notelcol_exporter_sent_metric_points_total{exporter=\"otlp/weaver\"} 0\n", "")
				return out + `# TYPE otelcol_exporter_queue_capacity gauge
otelcol_exporter_queue_capacity{exporter="otlp/weaver",data_type="metrics"} 500
`
			},
			want: 10*time.Second + dockerTapPoll,
		},
		{
			name: "metric receiver appears while queues settle",
			sample: func(elapsed time.Duration) string {
				switch {
				case elapsed < time.Second:
					return drainTelemetry(float64(elapsed/time.Millisecond), float64(elapsed/time.Millisecond), -1, -1)
				case elapsed < 3*time.Second:
					return drainTelemetry(1000, 1000, 100, 0)
				default:
					return drainTelemetry(1000, 1000, 100, 1)
				}
			},
			want: 3 * time.Second,
		},
		{
			name: "zero metric receiver becomes active while queues settle",
			sample: func(elapsed time.Duration) string {
				switch {
				case elapsed < time.Second:
					return drainTelemetry(float64(elapsed/time.Millisecond), float64(elapsed/time.Millisecond), 0, 0)
				case elapsed < 3*time.Second:
					return drainTelemetry(1000, 1000, 100, 0)
				default:
					return drainTelemetry(1000, 1000, 100, 1)
				}
			},
			want: 3 * time.Second,
		},
		{
			name: "one shot receipt and delivery in the same scrape",
			sample: func(elapsed time.Duration) string {
				if elapsed == 0 {
					return drainTelemetry(0, 0, 0, 0)
				}
				return drainTelemetry(1, 1, 100, 1)
			},
			want: 2 * dockerTapPoll,
		},
		{
			name: "idle producer with historical deliveries",
			sample: func(time.Duration) string {
				return drainTelemetry(10, 10, 100, 1)
			},
			want: dockerDrainWindow + dockerTapPoll,
		},
		{
			name: "queued exports settle only after two empty samples",
			sample: func(elapsed time.Duration) string {
				out := drainTelemetry(float64(elapsed/time.Millisecond), float64(elapsed/time.Millisecond), 0, 0)
				if elapsed < 3*dockerTapPoll {
					out = strings.Replace(out, "otelcol_exporter_queue_size{exporter=\"otlp/weaver\"} 0", "otelcol_exporter_queue_size{exporter=\"otlp/weaver\"} 1", 1)
				}
				return out
			},
			want: 4 * dockerTapPoll,
		},
		{
			name: "failed delivery remains available for warnings",
			sample: func(elapsed time.Duration) string {
				failed := 0
				if elapsed > 0 {
					failed = 1
				}
				return drainTelemetry(1, 1, 100, 0) + fmt.Sprintf(`# TYPE otelcol_exporter_send_failed_metric_points_total counter
otelcol_exporter_send_failed_metric_points_total{exporter="otlp/weaver"} %d
`, failed)
			},
			want: dockerDrainWindow + dockerTapPoll,
		},
		{
			name: "trace failure does not release buffered metrics",
			sample: func(elapsed time.Duration) string {
				sentMetrics := float64(0)
				if elapsed >= 10*time.Second {
					sentMetrics = 1
				}
				return drainTelemetry(float64(elapsed/time.Millisecond), float64(elapsed/time.Millisecond), 100, sentMetrics) + fmt.Sprintf(`# TYPE otelcol_exporter_send_failed_spans_total counter
otelcol_exporter_send_failed_spans_total{exporter="otlp/weaver"} %g
`, float64(elapsed/time.Second))
			},
			want: 10*time.Second + dockerTapPoll,
		},
		{
			name: "matching failure resolves a late metric delivery",
			sample: func(elapsed time.Duration) string {
				receivedMetrics, failedMetrics := float64(0), float64(0)
				if elapsed >= time.Second {
					receivedMetrics = 100
				}
				if elapsed >= 2*time.Second {
					failedMetrics = 1
				}
				return drainTelemetry(float64(elapsed/time.Millisecond), float64(elapsed/time.Millisecond), receivedMetrics, 0) + fmt.Sprintf(`# TYPE otelcol_exporter_send_failed_metric_points_total counter
otelcol_exporter_send_failed_metric_points_total{exporter="otlp/weaver"} %g
`, failedMetrics)
			},
			want: 2 * time.Second,
		},
		{
			name: "logs only tap does not wait for traces sent to a file",
			sample: func(elapsed time.Duration) string {
				return logsOnlyTapTelemetry(float64(elapsed / time.Millisecond))
			},
			want: 2 * dockerTapPoll,
		},
		{
			name: "untapped traces arriving while queues settle are ignored",
			sample: func(elapsed time.Duration) string {
				out := logsOnlyTapTelemetry(float64(elapsed / time.Millisecond))
				if elapsed < time.Second {
					out = strings.Replace(out, `otelcol_receiver_accepted_spans_total{receiver="otlp"}`, `otelcol_receiver_accepted_spans_total{receiver="otlp/apps"}`, 1)
				}
				return out
			},
			want: 2 * dockerTapPoll,
		},
		{
			name: "empty producer",
			sample: func(time.Duration) string {
				return drainTelemetry(0, 0, 0, 0)
			},
			want: dockerDrainWindow + dockerTapPoll,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				scrape := func(context.Context) (TapStats, error) {
					return ParseTapStats(strings.NewReader(test.sample(time.Since(started))), weaverTapExporter)
				}
				ctx, cancel := context.WithTimeout(context.Background(), dockerCollectorDrainTimeout)
				defer cancel()
				stats, err := waitForForwardedExport(ctx, scrape)
				require.NoError(t, err)
				stats, err = waitForSettledTap(ctx, scrape, stats)
				require.NoError(t, err)
				expected, err := ParseTapStats(strings.NewReader(test.sample(test.want)), weaverTapExporter)
				require.NoError(t, err)
				require.Equal(t, expected, stats)
				require.Equal(t, test.want, time.Since(started))
			})
		})
	}
}

func TestForwardedExportCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(dockerTapPoll, cancel)
		_, err := waitForForwardedExport(ctx, func(context.Context) (TapStats, error) {
			return ParseTapStats(strings.NewReader(drainTelemetry(1, 1, 100, 0)), weaverTapExporter)
		})
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestDrainScrapeErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		want := errors.New("collector unavailable")
		scrape := func(context.Context) (TapStats, error) { return TapStats{}, want }
		_, err := waitForForwardedExport(context.Background(), scrape)
		require.ErrorIs(t, err, want)
		_, err = waitForSettledTap(context.Background(), scrape, TapStats{})
		require.ErrorIs(t, err, want)
	})
}

func drainTelemetry(receivedSpans, sentSpans, receivedMetrics, sentMetrics float64) string {
	out := fmt.Sprintf(`# TYPE otelcol_receiver_accepted_spans_total counter
otelcol_receiver_accepted_spans_total{receiver="otlp"} %g
# TYPE otelcol_exporter_sent_spans_total counter
otelcol_exporter_sent_spans_total{exporter="otlp/weaver"} %g
# TYPE otelcol_exporter_queue_size gauge
otelcol_exporter_queue_size{exporter="otlp/weaver"} 0
`, receivedSpans, sentSpans)
	if receivedMetrics >= 0 {
		out += fmt.Sprintf(`# TYPE otelcol_receiver_accepted_metric_points_total counter
otelcol_receiver_accepted_metric_points_total{receiver="otlp"} %g
# TYPE otelcol_exporter_sent_metric_points_total counter
otelcol_exporter_sent_metric_points_total{exporter="otlp/weaver"} %g
`, receivedMetrics, sentMetrics)
	}
	return out
}

func logsOnlyTapTelemetry(received float64) string {
	return fmt.Sprintf(`# TYPE otelcol_receiver_accepted_spans_total counter
otelcol_receiver_accepted_spans_total{receiver="otlp"} %g
# TYPE otelcol_receiver_accepted_log_records_total counter
otelcol_receiver_accepted_log_records_total{receiver="otlp"} %g
# TYPE otelcol_exporter_sent_log_records_total counter
otelcol_exporter_sent_log_records_total{exporter="otlp/weaver"} %g
# TYPE otelcol_exporter_queue_size gauge
otelcol_exporter_queue_size{exporter="otlp/weaver",data_type="logs"} 0
`, received, received, received)
}
