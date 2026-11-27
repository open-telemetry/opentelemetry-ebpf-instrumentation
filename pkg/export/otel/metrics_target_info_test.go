// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
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
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestTargetInfoEnabled(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			names := exportedMetricNames(t, enabled)

			assert.Contains(t, names, attributes.HTTPClientDuration.OTEL)
			assert.Contains(t, names, attributes.SpanMetricsCallsOTel.OTEL)
			for _, name := range []string{TargetInfo, TracesTargetInfo} {
				_, found := names[name]
				assert.Equal(t, enabled, found, name)
			}
		})
	}
}

func exportedMetricNames(t *testing.T, targetInfo bool) map[string]struct{} {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const features = export.FeatureApplicationRED | export.FeatureSpanOTel
	records := make(chan collector.MetricRecord, 100)
	mcfg := shutdownTestConfig(records, 10)
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(0))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(0))
	reporter, err := newMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&perapp.GlobalMetricsConfig{
			Features:          features,
			DisableTargetInfo: !targetInfo,
		},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		spans,
		processEvents,
	)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		reporter.reportMetrics(ctx)
		close(done)
	}()

	service := svc.Attrs{Features: features, UID: svc.UID{Name: "svc", Instance: "svc-1"}}
	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 1, Service: service}),
	})
	spans.Send([]request.Span{httpClientSpan(service)})
	spans.Send([]request.Span{})

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "reportMetrics did not finish")
	}

	names := map[string]struct{}{}
	for {
		select {
		case record := <-records:
			names[record.Name] = struct{}{}
		default:
			return names
		}
	}
}
