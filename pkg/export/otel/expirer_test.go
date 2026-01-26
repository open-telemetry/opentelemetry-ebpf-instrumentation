// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 20 * time.Second

var mpConfig = perapp.MetricsConfig{Features: export.FeatureAll}

func TestNetMetricsExpiration(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	metrics := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(20))
	cfg := &otelcfg.MetricsConfig{
		Interval:        50 * time.Millisecond,
		CommonEndpoint:  otlp.ServerEndpoint,
		MetricsProtocol: otelcfg.ProtocolHTTPProtobuf,
		TTL:             3 * time.Minute,
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationALL,
		},
	}
	otelExporter, err := NetMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{
			Cfg: cfg,
		}}, &NetMetricsConfig{
			Metrics: cfg, SelectorCfg: &attributes.SelectorConfig{
				SelectionCfg: attributes.Selection{
					attributes.NetworkFlow.Section: attributes.InclusionLists{
						Include: []string{"src.name", "dst.name"},
					},
				},
			},
			CommonCfg: &perapp.MetricsConfig{Features: export.FeatureNetwork},
		}, metrics)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives metrics
	metrics.Send([]*ebpf.Record{
		{
			Attrs:          ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}},
		},
		{
			Attrs:          ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}},
		},
	})

	// THEN the metrics are exported
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Attributes["src.name"] != "foo" || metric.Attributes["dst.name"] != "bar" {
			return false
		}
		if metric.IntVal < 122.877 || metric.IntVal > 123.123 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Attributes["src.name"] != "baz" || metric.Attributes["dst.name"] != "bae" {
			return false
		}
		if metric.IntVal < 455.544 || metric.IntVal > 456.456 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)
	// AND WHEN it keeps receiving a subset of the initial metrics during the TTL
	now.Advance(2 * time.Minute)
	metrics.Send([]*ebpf.Record{
		{
			Attrs:          ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}},
		},
	})

	// THEN THE metrics that have been received during the TTL period are still visible
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Attributes["src.name"] != "foo" || metric.Attributes["dst.name"] != "bar" {
			return false
		}
		if metric.IntVal < 245.754 || metric.IntVal > 246.246 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)

	now.Advance(2 * time.Minute)
	metrics.Send([]*ebpf.Record{
		{
			Attrs:          ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}},
		},
	})

	// makes sure that the records channel is emptied and any remaining
	// old metric is sent and then the channel is re-emptied
	otlp.ResetRecords()
	readChan(t, otlp.Records())
	otlp.ResetRecords()

	// BUT not the metrics that haven't been received during that time.
	// We just know it because OTEL will only sends foo/bar metric.
	// If this test is flaky: it means it is actually failing
	// repeating 10 times to make sure that only this metric is forwarded
	for range 10 {
		metric := readChan(t, otlp.Records())
		require.Equal(t, map[string]string{"src.name": "foo", "dst.name": "bar"}, metric.Attributes)
		require.InEpsilon(t, 369, metric.IntVal, 0.001)
	}

	// AND WHEN the metrics labels that disappeared are received again
	now.Advance(2 * time.Minute)
	metrics.Send([]*ebpf.Record{
		{
			Attrs:          ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}},
		},
	})

	// THEN they are reported again, starting from zero in the case of counters
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Attributes["src.name"] != "baz" || metric.Attributes["dst.name"] != "bae" {
			return false
		}
		if metric.IntVal < 455.544 || metric.IntVal > 456.456 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)
}

// the expiration logic is held at two levels:
// (1) by group of attributes within the same service Attrs,
// (2) by metric set of a given service Attrs
// this test verifies case 1
func TestAppMetricsExpiration_ByMetricAttrs(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	var g attributes.AttrGroups
	g.Add(attributes.GroupKubernetes)

	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	cfg := &otelcfg.MetricsConfig{
		Interval:          50 * time.Millisecond,
		CommonEndpoint:    otlp.ServerEndpoint,
		MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
		TTL:               3 * time.Minute,
		ReportersCacheLen: 100,
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationALL,
		},
	}
	otelExporter, err := ReportMetrics(
		&global.ContextInfo{
			MetricAttributeGroups: g,
			OTELMetricsExporter:   &otelcfg.MetricsExporterInstancer{Cfg: cfg},
		}, cfg, &mpConfig, &attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.HTTPServerDuration.Section: attributes.InclusionLists{
					Include: []string{"url.path", "k8s.app.version"},
				},
			},
			ExtraGroupAttributesCfg: map[string][]attr.Name{
				"k8s_app_meta": {"k8s.app.version"},
			},
		}, request.UnresolvedNames{}, metrics, processEvents)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives metrics
	metrics.Send([]request.Span{
		{
			Service: svc.Attrs{
				Features: export.FeatureAll,
				UID:      svc.UID{Instance: "foo"},
				Metadata: map[attr.Name]string{
					"k8s.app.version": "v0.0.1",
				},
			},
			Type:         request.EventTypeHTTP,
			Path:         "/foo",
			RequestStart: 100,
			End:          200,
		},
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/bar", RequestStart: 150, End: 175},
	})

	// THEN the metrics are exported
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		// k8s.app.version attribute is missing because the otel exporter
		// does not read values from span metadata
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/foo" {
			return false
		}
		expected := 100 / float64(time.Second)
		if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
			return false
		}
		if metric.Count != 1 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)

	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/bar" {
			return false
		}
		expected := 25 / float64(time.Second)
		if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
			return false
		}
		if metric.Count != 1 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)

	// AND WHEN it keeps receiving a subset of the initial metrics during the TTL
	now.Advance(2 * time.Minute)
	metrics.Send([]request.Span{
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 250, End: 280},
	})

	// THEN THE metrics that have been received during the TTL period are still visible
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/foo" {
			return false
		}
		expected := 130 / float64(time.Second)
		if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
			return false
		}
		if metric.Count != 2 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)

	now.Advance(2 * time.Minute)
	metrics.Send([]request.Span{
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 300, End: 310},
	})

	// makes sure that the records channel is emptied and any remaining
	// old metric is sent and then the channel is re-emptied
	otlp.ResetRecords()
	readChan(t, otlp.Records())
	otlp.ResetRecords()

	// BUT not the metrics that haven't been received during that time.
	// We just know it because OTEL will only sends foo/bar metric.
	// If this test is flaky: it means it is actually failing
	// repeating 10 times to make sure that only this metric is forwarded
	for i := 0; i < 10; i++ {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			// ignore other HTTP metrics (e.g. request size)
			i--
			continue
		}
		require.Equal(t, map[string]string{"url.path": "/foo"}, metric.Attributes)
		require.InEpsilon(t, 140/float64(time.Second), metric.FloatVal, 0.001)
		assert.Equal(t, 3, metric.Count)
	}

	// AND WHEN the metrics labels that disappeared are received again
	now.Advance(2 * time.Minute)
	metrics.Send([]request.Span{
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/bar", RequestStart: 450, End: 520},
	})

	// THEN they are reported again, starting from zero in the case of counters
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/bar" {
			return false
		}
		expected := 70 / float64(time.Second)
		if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
			return false
		}
		if metric.Count != 1 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)
}

// the expiration logic is held at two levels:
// (1) by group of attributes within the same service Attrs,
// (2) by metric set of a given service Attrs
// this test verifies case 2
func TestAppMetricsExpiration_BySvcID(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	cfg := &otelcfg.MetricsConfig{
		Interval:          50 * time.Millisecond,
		CommonEndpoint:    otlp.ServerEndpoint,
		MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
		TTL:               3 * time.Minute,
		ReportersCacheLen: 100,
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationALL,
		},
	}
	otelExporter, err := ReportMetrics(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		cfg, &mpConfig,
		&attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.HTTPServerDuration.Section: attributes.InclusionLists{
					Include: []string{"url.path"},
				},
			},
		}, request.UnresolvedNames{}, metrics, processEvents)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives metrics
	metrics.Send([]request.Span{
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "bar"}}, Type: request.EventTypeHTTP, Path: "/bar", RequestStart: 150, End: 175},
	})

	// THEN the metrics are exported
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/foo" {
			return false
		}
		expected := 100 / float64(time.Second)
		if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
			return false
		}
		if metric.Count != 1 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)

	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/bar" {
			return false
		}
		expected := 25 / float64(time.Second)
		if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
			return false
		}
		if metric.Count != 1 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)

	// AND WHEN it keeps receiving a subset of the initial metrics during the TTL
	now.Advance(2 * time.Minute)
	metrics.Send([]request.Span{
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 250, End: 280},
	})

	// THEN THE metrics that have been received during the TTL period are still visible
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/foo" {
			return false
		}
		expected := 130 / float64(time.Second)
		if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
			return false
		}
		if metric.Count != 2 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)

	now.Advance(2 * time.Minute)
	metrics.Send([]request.Span{
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 300, End: 310},
	})

	// BUT not the metrics that haven't been received during that time.
	// We just know it because OTEL will only sends foo/bar metric.
	// If this test is flaky: it means it is actually failing
	// repeating 10 times to make sure that only this metric is forwarded
	// need to wait until expireCache internal goroutine removes all the expired entries
	require.Eventually(t, func() bool {
		// makes sure that the records channel is emptied and any remaining
		// old metric is sent and then the channel is re-emptied
		otlp.ResetRecords()
		readChan(t, otlp.Records())
		otlp.ResetRecords()
		for i := 0; i < 10; i++ {
			metric := readChan(t, otlp.Records())
			if metric.Name != "http.server.request.duration" {
				// ignore other HTTP metrics (e.g. request size)
				i--
				continue
			}
			if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/foo" {
				return false
			}
			expected := 140 / float64(time.Second)
			if metric.FloatVal < expected*0.999 || metric.FloatVal > expected*1.001 {
				return false
			}
			if metric.Count != 3 {
				return false
			}
		}
		return true
	}, timeout, 100*time.Millisecond)
	// AND WHEN the metrics labels that disappeared are received again
	now.Advance(2 * time.Minute)
	metrics.Send([]request.Span{
		{Service: svc.Attrs{Features: export.FeatureAll, UID: svc.UID{Instance: "bar"}}, Type: request.EventTypeHTTP, Path: "/bar", RequestStart: 450, End: 520},
	})

	// THEN they are reported again, starting from zero in the case of counters
	require.Eventually(t, func() bool {
		metric := readChan(t, otlp.Records())
		if metric.Name != "http.server.request.duration" {
			return false
		}
		if len(metric.Attributes) != 1 || metric.Attributes["url.path"] != "/bar" {
			return false
		}
		expected := 70 / float64(time.Second)
		if metric.FloatVal < expected*0.9999 || metric.FloatVal > expected*1.0001 {
			return false
		}
		if metric.Count != 1 {
			return false
		}
		return true
	}, timeout, 100*time.Millisecond)
}

type syncedClock struct {
	mt  sync.Mutex
	now time.Time
}

func (c *syncedClock) Now() time.Time {
	c.mt.Lock()
	defer c.mt.Unlock()
	return c.now
}

func (c *syncedClock) Advance(t time.Duration) {
	c.mt.Lock()
	defer c.mt.Unlock()
	c.now = c.now.Add(t)
}

func readChan(t require.TestingT, inCh <-chan collector.MetricRecord) collector.MetricRecord {
	select {
	case item := <-inCh:
		return item
	case <-time.After(timeout):
		require.Failf(t, "timeout while waiting for event in input channel", "timeout: %s", timeout)
	}
	return collector.MetricRecord{}
}
