// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestInternalMetricsFinalExportCoversDrain(t *testing.T) {
	coll, err := collector.Start(t.Context())
	require.NoError(t, err)

	cfg := obi.DefaultConfig
	cfg.OTELMetrics.CommonEndpoint = coll.ServerEndpoint
	cfg.OTELMetrics.Interval = time.Hour
	cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterOTEL
	cfg.Attributes.MetadataRetry = metadata.RetryConfig{Timeout: time.Millisecond}
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledFalse

	ctx, signal := context.WithCancel(t.Context())
	defer signal()
	ctxInfo, err := BuildCommonContextInfo(ctx, &cfg)
	require.NoError(t, err)

	shutdownBudget, cancelShutdownBudget := shutdownBudgetContext(ctx, cfg.ShutdownTimeout)
	defer cancelShutdownBudget()

	signal()
	require.NoError(t, shutdownBudget.Err())

	ctxInfo.Metrics.TracerFlush(3)
	shutdownInternalMetrics(shutdownBudget, ctxInfo.Metrics)

	tracerFlushes := attributes.NewInternalMetrics(attr.VendorPrefix).TracerFlushes.OTEL
	require.Eventually(t, func() bool {
		for {
			select {
			case rec := <-coll.Records():
				if rec.Name == tracerFlushes && rec.Count == 1 {
					return true
				}
			default:
				return false
			}
		}
	}, 10*time.Second, 20*time.Millisecond, "the value recorded after the signal must be exported")
}

func TestShutdownBudgetContextExpiresAfterTheSignal(t *testing.T) {
	ctx, signal := context.WithCancel(t.Context())
	defer signal()

	const budget = 50 * time.Millisecond
	shutdownBudget, cancelShutdownBudget := shutdownBudgetContext(ctx, budget)
	defer cancelShutdownBudget()

	time.Sleep(2 * budget)
	require.NoError(t, shutdownBudget.Err())

	signal()
	require.NoError(t, shutdownBudget.Err())
	assert.Eventually(t, func() bool {
		return shutdownBudget.Err() != nil
	}, 5*time.Second, 5*time.Millisecond)
}
