// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pmetric"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestPeerMetadataServiceGraphEligibility(t *testing.T) {
	for _, exporter := range []string{"otel", "prometheus"} {
		for _, test := range []struct {
			name      string
			features  export.Features
			ruleGraph bool
			wantGraph bool
		}{
			{name: "application metrics only", features: export.FeatureApplicationRED},
			{name: "global service graph", features: export.FeatureApplicationRED | export.FeatureGraph, wantGraph: true},
			{name: "per-service graph", features: export.FeatureApplicationRED, ruleGraph: true, wantGraph: true},
		} {
			t.Run(exporter+"/"+test.name, func(t *testing.T) {
				cfg := obi.DefaultConfig
				cfg.NameResolver = nil
				cfg.Metrics.Features = test.features
				cfg.PeerMetadata = peer.DefaultConfig()
				cfg.PeerMetadata.Enabled = true
				cfg.PeerMetadata.ListenAddress = "127.0.0.1"
				cfg.PeerMetadata.PeerCIDRs = []string{"127.0.0.0/8"}
				cfg.PeerMetadata.Port = testutil.FreeTCPPort(t)
				cfg.Attributes.InstanceID.OverrideHostname = "peer-host"
				if test.ruleGraph {
					cfg.Discovery.Instrument = services.GlobDefinitionCriteria{{
						Path:    services.NewGlob("service"),
						Metrics: perapp.SvcMetricsConfig{Features: export.FeatureGraph},
					}}
				}
				info := gctx(0, &cfg.OTELMetrics)
				if exporter == "otel" {
					cfg.OTELMetrics.MetricsExport = func(context.Context, pmetric.Metrics) error { return nil }
				} else {
					server := testutil.NewPrometheusServer(t)
					cfg.Prometheus.Port = server.Port
					info.Prometheus = server.Manager
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				input := msg.NewQueue[[]request.Span]()
				events := msg.NewQueue[exec.ProcessEvent]()
				pipeline, err := Build(ctx, &cfg, info, input, events, nil)
				require.NoError(t, err)
				done := pipeline.Start(ctx)
				defer func() { cancel(); require.NoError(t, <-done) }()

				client := &http.Client{Timeout: time.Second}
				defer client.CloseIdleConnections()
				endpoint := "http://127.0.0.1:" + strconv.Itoa(cfg.PeerMetadata.Port) + peer.MetadataPath
				response, err := client.Get(endpoint)
				require.NoError(t, err)
				defer response.Body.Close()
				require.Equal(t, http.StatusOK, response.StatusCode)
				var snapshot peer.Snapshot
				require.NoError(t, json.NewDecoder(response.Body).Decode(&snapshot))
				require.Equal(t, "peer-host", snapshot.Hostname)
				require.Empty(t, snapshot.Listeners)
				if test.wantGraph {
					require.NotNil(t, snapshot.MetricProtocols)
					require.True(t, snapshot.MetricProtocols.HTTPEnabled())
				} else {
					require.Nil(t, snapshot.MetricProtocols, "application metrics alone must not suppress remote client graph counts")
				}
			})
		}
	}
}
