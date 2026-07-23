// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestInternalMetricsResourceHasHostMetadata(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coll, err := collector.Start(ctx)
	require.NoError(t, err)

	const hostID = "test-host-id"
	cfg := obi.DefaultConfig
	cfg.OTELMetrics.CommonEndpoint = coll.ServerEndpoint
	cfg.OTELMetrics.Interval = 10 * time.Millisecond
	cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterOTEL
	cfg.Attributes.HostID.Override = hostID
	cfg.Attributes.MetadataRetry = meta.RetryConfig{Timeout: time.Millisecond}
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledFalse

	ctxInfo, err := BuildCommonContextInfo(ctx, &cfg)
	require.NoError(t, err)
	require.Equal(t, hostID, ctxInfo.NodeMeta.HostID)

	ctxInfo.Metrics.Start(ctx)

	require.Eventually(t, func() bool {
		select {
		case rec := <-coll.Records():
			return rec.ResourceAttributes["host.id"] == hostID
		default:
			return false
		}
	}, 10*time.Second, 20*time.Millisecond, "internal metrics must carry the host.id resource attribute")
}
