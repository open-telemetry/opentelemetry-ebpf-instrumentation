// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func TestServiceGraphMetrics(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer otelcfg.RestoreEnvAfterExecution()()

	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))

	otelExporter := makeSvcGraphExporter(ctx, t, otlp, metrics, processEvents)

	require.NoError(t, err)
	go func() {
		otelExporter(ctx)
	}()

	clientID := svc.Attrs{Features: export.FeatureAll, ProcPID: 33, UID: svc.UID{Name: "client", Instance: "the-client"}}
	serverID := svc.Attrs{Features: export.FeatureAll, ProcPID: 66, UID: svc.UID{Name: "server", Instance: "the-server"}}

	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: &exec.FileInfo{Service: clientID, Pid: clientID.ProcPID},
	})
	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: &exec.FileInfo{Service: serverID, Pid: serverID.ProcPID},
	})

	metrics.Send([]request.Span{
		{Service: serverID, Type: request.EventTypeHTTP, Peer: "client-host", Host: "server-host", Path: "/foo", RequestStart: 100, End: 200},
		{Service: clientID, Type: request.EventTypeHTTPClient, Peer: "server-host", Host: "client-host", Path: "/bar", RequestStart: 150, End: 175},
	})

	// Read the exported metrics, add +extraColl for HTTP size metrics
	res := readNChan(t, otlp.Records(), 6, timeout)
	assert.NotEmpty(t, res)
	reported := map[string]struct{}{}
	for _, m := range res {
		reported[m.Name+":"+m.Attributes["client"]+":"+m.Attributes["server"]] = struct{}{}
	}

	require.Equal(t, map[string]struct{}{
		"traces_service_graph_request_client:server-host:client-host":       {},
		"traces_service_graph_request_server:client-host:server-host":       {},
		"traces_service_graph_request_failed_total:server-host:client-host": {},
		"traces_service_graph_request_failed_total:client-host:server-host": {},
		"traces_service_graph_request_total:client-host:server-host":        {},
	}, reported)
}

func TestServiceGraphConnectionType(t *testing.T) {
	t.Skip("flaky")
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer otelcfg.RestoreEnvAfterExecution()()

	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))

	otelExporter := makeSvcGraphExporter(ctx, t, otlp, metrics, processEvents)

	require.NoError(t, err)
	go func() {
		otelExporter(ctx)
	}()

	clientID := svc.Attrs{ProcPID: 33, UID: svc.UID{Name: "client", Instance: "the-client"}, Features: export.FeatureAll}

	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: &exec.FileInfo{Service: clientID, Pid: clientID.ProcPID},
	})

	// Send database client spans
	metrics.Send([]request.Span{
		{Service: clientID, Type: request.EventTypeSQLClient, HostName: "postgres-db", Host: "client-host", Method: "SELECT", Path: "users", RequestStart: 100, End: 200},
		{Service: clientID, Type: request.EventTypeRedisClient, HostName: "redis-cache", Host: "client-host", Method: "GET", RequestStart: 150, End: 175},
		{Service: clientID, Type: request.EventTypeKafkaClient, HostName: "kafka-broker", Host: "client-host", Method: request.MessagingPublish, Path: "topic1", RequestStart: 200, End: 250},
	})

	// Read the exported metrics
	res := readNChan(t, otlp.Records(), 9, timeout)
	assert.NotEmpty(t, res)

	// Check connection_type for each metric
	for _, m := range res {
		connType := m.Attributes["connection_type"]
		server := m.Attributes["server"]

		switch server {
		case "postgres-db", "redis-cache":
			assert.Equal(t, "database", connType, "Database spans should have connection_type=database for server=%s", server)
		case "kafka-broker":
			assert.Equal(t, "messaging_system", connType, "Kafka spans should have connection_type=messaging_system for server=%s", server)
		}
	}
}

func makeSvcGraphExporter(
	ctx context.Context, t *testing.T, otlp *collector.TestCollector,
	input *msg.Queue[[]request.Span],
	processEvents *msg.Queue[exec.ProcessEvent],
) swarm.RunFunc {
	mcfg := &otelcfg.MetricsConfig{
		Interval:          50 * time.Millisecond,
		CommonEndpoint:    otlp.ServerEndpoint,
		MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
		TTL:               30 * time.Minute,
		ReportersCacheLen: 100,
		Instrumentations:  []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}
	otelExporter, err := ReportSvcGraphMetrics(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg, &mpConfig, request.UnresolvedNames{}, input, processEvents)(ctx)
	require.NoError(t, err)

	return otelExporter
}
