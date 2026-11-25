// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const targetInfoTestFeatures = export.FeatureApplicationRED | export.FeatureSpanOTel | export.FeatureApplicationRuntime

func newTargetInfoTestReporter(t *testing.T, enabled bool) (*metricsReporter, prometheus.Gatherer) {
	t.Helper()

	registry := testutil.NewPrometheusServer(t)
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: registry.Manager},
		&PrometheusConfig{Port: registry.Port, Path: "/metrics", TTL: time.Minute, SpanMetricsServiceCacheSize: 10},
		&perapp.GlobalMetricsConfig{
			Features:          targetInfoTestFeatures,
			DisableTargetInfo: !enabled,
		},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
		nil,
	)
	require.NoError(t, err)
	return reporter, registry
}

func targetInfoTestService() svc.Attrs {
	return svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		ProcPID:     101,
		SDKLanguage: svc.InstrumentableGolang,
		Features:    targetInfoTestFeatures,
	}
}

func gatheredFamilies(t *testing.T, registry prometheus.Gatherer) map[string][]map[string]string {
	t.Helper()

	families, err := registry.Gather()
	require.NoError(t, err)
	byName := map[string][]map[string]string{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			byName[family.GetName()] = append(byName[family.GetName()], labels)
		}
	}
	return byName
}

func TestTargetInfoEnabled(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			reporter, registry := newTargetInfoTestReporter(t, enabled)
			service := targetInfoTestService()

			reporter.createTargetInfos(&service)
			families := gatheredFamilies(t, registry)
			for _, name := range []string{TargetInfo, TracesTargetInfo} {
				_, found := families[name]
				assert.Equal(t, enabled, found, name)
			}

			reporter.deleteTargetInfoMetrics(&service)
			families = gatheredFamilies(t, registry)
			assert.NotContains(t, families, TargetInfo)
			assert.NotContains(t, families, TracesTargetInfo)
		})
	}
}

func TestTargetInfoDisabledKeepsRuntimeMetricLabels(t *testing.T) {
	goroutineLabels := func(enabled bool) []map[string]string {
		reporter, registry := newTargetInfoTestReporter(t, enabled)
		goroutines := int64(12)
		reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
			Service: targetInfoTestService(),
			Go:      &runtimemetrics.GoRuntimeMetricSnapshot{GoroutineCount: &goroutines},
		}})
		labels := gatheredFamilies(t, registry)["go_goroutine_count"]
		require.Len(t, labels, 1)
		return labels
	}

	enabled := goroutineLabels(true)
	disabled := goroutineLabels(false)
	assert.Equal(t, enabled, disabled)
	assert.Equal(t, "orders", disabled[0]["service_name"])
	assert.Equal(t, "prod/orders", disabled[0]["job"])
}
