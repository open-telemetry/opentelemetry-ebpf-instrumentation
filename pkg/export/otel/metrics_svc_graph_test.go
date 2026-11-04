// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel/attribute"

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
	"go.opentelemetry.io/obi/pkg/kube"
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
		File: exec.New(exec.Init{Service: clientID, Pid: clientID.ProcPID}),
	})
	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Service: serverID, Pid: serverID.ProcPID}),
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
		if ct, ok := m.Attributes["connection_type"]; ok {
			assert.Fail(t, "direct HTTP requests must omit connection_type", "metric %s got connection_type=%q", m.Name, ct)
		}
	}

	require.Equal(t, map[string]struct{}{
		"traces_service_graph_request_client:server-host:client-host":       {},
		"traces_service_graph_request_server:client-host:server-host":       {},
		"traces_service_graph_request_failed_total:server-host:client-host": {},
		"traces_service_graph_request_failed_total:client-host:server-host": {},
		"traces_service_graph_request_total:client-host:server-host":        {},
	}, reported)
}

func TestConnectionInfoTTLPreventsOTLPReporterEvictionAtMetricsTTL(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Unix(100, 0).UnixNano())
	previousTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(0, now.Load()) }
	t.Cleanup(func() { timeNow = previousTimeNow })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	metricCfg := &otelcfg.MetricsConfig{
		TTL:               5 * time.Minute,
		ConnectionInfoTTL: 15 * time.Minute,
		ReportersCacheLen: 10,
		MetricsExport: func(context.Context, pmetric.Metrics) error {
			return nil
		},
	}
	exporter := &otelcfg.MetricsExporterInstancer{Cfg: metricCfg}
	jointConfig := &perapp.GlobalMetricsConfig{Features: export.FeatureGraph | export.FeatureConnectionInfo}
	reporter, err := newSvcGraphMetricsReporter(
		ctx,
		&global.ContextInfo{K8sInformer: &kube.MetadataProvider{}, OTELMetricsExporter: exporter},
		metricCfg,
		jointConfig,
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1)),
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)

	service := &svc.Attrs{UID: svc.UID{Name: "frontend", Namespace: "shop"}}
	first, err := reporter.reporters.For(service)
	require.NoError(t, err)
	now.Add(int64(6 * time.Minute))
	stillCached, err := reporter.reporters.For(service)
	require.NoError(t, err)
	assert.Same(t, first, stillCached, "connection-info reporter should survive beyond global metrics TTL")

	ctxDone, shutdownCancel := context.WithTimeout(ctx, time.Second)
	defer shutdownCancel()
	require.NoError(t, first.provider.Shutdown(ctxDone))
	require.NoError(t, reporter.exporter.Shutdown(ctxDone))
}

func TestConnectionInfoEmitsPresenceGaugeFromOneClientSpan(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()
	otlp, err := collector.Start(ctx)
	require.NoError(t, err)
	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	metricCfg := &otelcfg.MetricsConfig{
		Interval:          50 * time.Millisecond,
		CommonEndpoint:    otlp.ServerEndpoint,
		MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
		TTL:               time.Minute,
		ReportersCacheLen: 10,
		Instrumentations:  []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}
	features := export.Features(export.FeatureConnectionInfo)
	run, err := ReportSvcGraphMetrics(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: metricCfg}},
		metricCfg, &perapp.GlobalMetricsConfig{Features: features}, &attributes.SelectorConfig{},
		request.UnresolvedNames{}, metrics, processEvents,
	)(ctx)
	require.NoError(t, err)
	go run(ctx)

	client := svc.Attrs{Features: features, UID: svc.UID{Name: "frontend", Namespace: "shop"}}
	metrics.Send([]request.Span{{
		Service:        client,
		Type:           request.EventTypeHTTPClient,
		Host:           "frontend-pod",
		HostName:       "catalog",
		OtherNamespace: "shop",
	}})

	records := readNChan(t, otlp.Records(), 2, timeout)
	for _, record := range records {
		require.Equal(t, attributes.ServiceGraphConnectionInfo.OTEL, record.Name)
		assert.Equal(t, int64(1), record.IntVal)
		assert.Equal(t, "frontend", record.Attributes["client"])
		assert.Equal(t, "catalog", record.Attributes["server"])
	}
}

func TestConnectionInfoScheduledExpiryIsIndependentFromGraphMetrics(t *testing.T) {
	for _, serverOnly := range []bool{false, true} {
		name := "idle"
		if serverOnly {
			name = "server-only activity"
		}
		t.Run(name, func(t *testing.T) {
			var now atomic.Int64
			now.Store(time.Unix(100, 0).UnixNano())
			previousTimeNow := timeNow
			timeNow = func() time.Time { return time.Unix(0, now.Load()) }
			t.Cleanup(func() { timeNow = previousTimeNow })

			ctx, cancel := context.WithCancel(t.Context())
			metricCfg := &otelcfg.MetricsConfig{
				Interval:          10 * time.Millisecond,
				TTL:               100 * time.Millisecond,
				ConnectionInfoTTL: 300 * time.Millisecond,
				ReportersCacheLen: 10,
				MetricsExport:     func(context.Context, pmetric.Metrics) error { return nil },
			}
			features := export.FeatureGraph | export.FeatureConnectionInfo
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))
			reporter, err := newSvcGraphMetricsReporter(
				ctx,
				&global.ContextInfo{K8sInformer: &kube.MetadataProvider{}, OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: metricCfg}},
				metricCfg, &perapp.GlobalMetricsConfig{Features: features}, &attributes.SelectorConfig{},
				request.UnresolvedNames{}, input, processEvents,
			)
			require.NoError(t, err)
			var frontendMetrics, graphOnlyMetrics *SvcGraphMetrics
			done := make(chan struct{})
			loopStarted := false
			t.Cleanup(func() {
				cancel()
				if loopStarted {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("metrics reporter did not stop")
					}
				}
				for _, metrics := range []*SvcGraphMetrics{frontendMetrics, graphOnlyMetrics} {
					if metrics == nil {
						continue
					}
					metrics.cleanupAllMetricsInstances()
					_ = metrics.provider.Shutdown(context.Background())
				}
			})

			client := svc.Attrs{Features: features, UID: svc.UID{Name: "frontend", Namespace: "shop"}}
			graphOnly := svc.Attrs{Features: export.FeatureGraph, UID: svc.UID{Name: "graph-only", Namespace: "shop"}}
			reporter.onSpan([]request.Span{{
				Service: client, Type: request.EventTypeHTTPClient, Host: "frontend-pod", Peer: "client-host", HostName: "10.0.0.8", OtherNamespace: "shop",
				RequestStart: 100, End: 200, ResponseObservation: request.ResponseReceived,
			}, {
				Service: graphOnly, Type: request.EventTypeHTTPClient, Host: "graph-only-pod", Peer: "graph-client", HostName: "upstream", OtherNamespace: "shop",
				RequestStart: 100, End: 200, ResponseObservation: request.ResponseReceived,
			}})
			frontendMetrics, err = reporter.reporters.For(&client)
			require.NoError(t, err)
			graphOnlyMetrics, err = reporter.reporters.For(&graphOnly)
			require.NoError(t, err)
			require.Len(t, frontendMetrics.connectionInfo.entries.All(), 1)
			require.Len(t, frontendMetrics.serviceGraphClient.entries.All(), 1)
			require.Len(t, graphOnlyMetrics.serviceGraphClient.entries.All(), 1)
			require.Len(t, frontendMetrics.serviceGraphTotal.entries.All(), 1)
			require.Len(t, graphOnlyMetrics.serviceGraphTotal.entries.All(), 1)

			loopStarted = true
			go func() {
				defer close(done)
				reporter.reportMetrics(ctx)
			}()

			now.Add(int64(110 * time.Millisecond))
			if serverOnly {
				input.Send([]request.Span{{
					Service: client, Type: request.EventTypeHTTP, Host: "frontend-pod", Peer: "client-host", HostName: "frontend", RequestStart: 200, End: 300,
					ResponseObservation: request.ResponseReceived,
				}})
			}
			require.Eventually(t, func() bool {
				wantFrontendTotal := 0
				wantServer := 0
				if serverOnly {
					wantFrontendTotal = 1
					wantServer = 1
				}
				return len(frontendMetrics.serviceGraphTotal.entries.All()) == wantFrontendTotal &&
					len(graphOnlyMetrics.serviceGraphTotal.entries.All()) == 0 &&
					len(frontendMetrics.serviceGraphClient.entries.All()) == 0 &&
					len(graphOnlyMetrics.serviceGraphClient.entries.All()) == 0 &&
					len(frontendMetrics.connectionInfo.entries.All()) == 1 &&
					len(frontendMetrics.serviceGraphServer.entries.All()) == wantServer
			}, timeout, 10*time.Millisecond, "graph series should expire while the connection edge remains")

			now.Add(int64(210 * time.Millisecond))
			if serverOnly {
				input.Send([]request.Span{{
					Service: client, Type: request.EventTypeHTTP, Host: "frontend-pod", Peer: "client-host", HostName: "frontend", RequestStart: 300, End: 400,
					ResponseObservation: request.ResponseReceived,
				}})
			}
			require.Eventually(t, func() bool {
				return len(frontendMetrics.connectionInfo.entries.All()) == 0
			}, timeout, 10*time.Millisecond, "connection edge must expire on timer without another client observation")
		})
	}
}

func TestConnectionInfoOnlyCreatesConnectionInfoInstrument(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()
	metricCfg := &otelcfg.MetricsConfig{
		Interval:          50 * time.Millisecond,
		CommonEndpoint:    "http://localhost:4318",
		TTL:               time.Minute,
		ReportersCacheLen: 10,
	}
	exporter, err := (&otelcfg.MetricsExporterInstancer{Cfg: metricCfg}).Instantiate(ctx)
	require.NoError(t, err)

	reporter := &SvcGraphMetricsReporter{
		ctx:                   ctx,
		cfg:                   metricCfg,
		exporter:              exporter,
		metricAttributes:      serviceGraphGetters(request.UnresolvedNames{}, false),
		serviceGraphEnabled:   false,
		connectionInfoEnabled: true,
		log:                   sglog(),
	}
	metrics, err := reporter.newMetricSet(nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		metrics.cleanupAllMetricsInstances()
		_ = metrics.provider.Shutdown(ctx)
		_ = exporter.Shutdown(ctx)
	})

	assert.NotNil(t, metrics.connectionInfo)
	assert.Nil(t, metrics.serviceGraphClient)
	assert.Nil(t, metrics.serviceGraphServer)
	assert.Nil(t, metrics.serviceGraphFailed)
	assert.Nil(t, metrics.serviceGraphTotal)
}

func TestConnectionInfoTTLIsIndependentFromMetricsTTL(t *testing.T) {
	assert.Equal(t, 5*time.Minute, serviceGraphReporterTTL(5*time.Minute, 15*time.Minute, false))
	assert.Equal(t, 15*time.Minute, serviceGraphReporterTTL(5*time.Minute, 15*time.Minute, true))
	assert.Equal(t, 5*time.Minute, serviceGraphReporterTTL(5*time.Minute, 3*time.Minute, true))
	assert.Equal(t, export.DefaultConnectionInfoTTL, export.ConnectionInfoTTLOrDefault(0))
	assert.Equal(t, 5*time.Second, connectionInfoExpiryInterval(10*time.Second, 5*time.Second, 15*time.Second))
	assert.Equal(t, 5*time.Second, connectionInfoExpiryInterval(0, 5*time.Second, 15*time.Second))

	metricCfg := &otelcfg.MetricsConfig{TTL: 5 * time.Minute, ConnectionInfoTTL: 15 * time.Minute}
	reporter := &SvcGraphMetricsReporter{
		ctx:                   t.Context(),
		cfg:                   metricCfg,
		serviceGraphEnabled:   true,
		connectionInfoEnabled: true,
		log:                   sglog(),
		metricAttributes:      serviceGraphGetters(request.UnresolvedNames{}, false),
		exporter:              otelcfg.NewOTLPConsumerExporter(nil),
	}
	metrics := reporter.newSvcGraphMetricsInstance(nil)
	require.NoError(t, reporter.setupGraphMeters(metrics, metrics.provider.Meter(reporterName)))
	assert.Equal(t, 15*time.Minute, metrics.connectionInfo.ttl)
	assert.Equal(t, 5*time.Minute, metricCfg.TTL)
	assert.Equal(t, 5*time.Minute, metrics.serviceGraphClient.ttl)
	assert.Equal(t, 5*time.Minute, metrics.serviceGraphTotal.ttl)

	assert.Equal(t, 15*time.Minute, serviceGraphReporterTTL(metricCfg.TTL, metricCfg.ConnectionInfoTTL, true))
	t.Cleanup(func() { _ = metrics.provider.Shutdown(t.Context()) })
}

func TestConnectionInfoConnectionTypeAttribute(t *testing.T) {
	tracker := NewPidServiceTracker()
	tracker.AddPID(1, svc.UID{Name: "catalog", Namespace: "shop"})
	fields := serviceGraphGetters(request.UnresolvedNames{Outgoing: "outgoing"}, false)

	for _, test := range []struct {
		name          string
		span          request.Span
		wantConnType  string
		wantAttribute bool
	}{
		{
			name: "direct HTTP is omitted",
			span: request.Span{
				Type:           request.EventTypeHTTPClient,
				Service:        svc.Attrs{UID: svc.UID{Name: "frontend", Namespace: "shop"}},
				HostName:       "catalog",
				OtherNamespace: "shop",
			},
		},
		{
			name: "raw IP remains a distinct destination",
			span: request.Span{
				Type:     request.EventTypeHTTPClient,
				Service:  svc.Attrs{UID: svc.UID{Name: "frontend", Namespace: "shop"}},
				HostName: "10.0.0.8",
			},
			wantConnType:  "virtual_node",
			wantAttribute: true,
		},
		{
			name: "raw IPv6 remains a distinct destination",
			span: request.Span{
				Type:     request.EventTypeHTTPClient,
				Service:  svc.Attrs{UID: svc.UID{Name: "frontend", Namespace: "shop"}},
				HostName: "2001:db8::8",
			},
			wantConnType:  "virtual_node",
			wantAttribute: true,
		},
		{
			name: "database",
			span: request.Span{
				Type:           request.EventTypeSQLClient,
				Service:        svc.Attrs{UID: svc.UID{Name: "frontend", Namespace: "shop"}},
				HostName:       "postgres",
				OtherNamespace: "shop",
			},
			wantConnType:  "database",
			wantAttribute: true,
		},
		{
			name: "messaging",
			span: request.Span{
				Type:           request.EventTypeKafkaClient,
				Service:        svc.Attrs{UID: svc.UID{Name: "frontend", Namespace: "shop"}},
				HostName:       "broker",
				OtherNamespace: "shop",
			},
			wantConnType:  "messaging_system",
			wantAttribute: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			getters := connectionInfoGetters(fields)
			values := make([]attribute.KeyValue, 0, len(getters)+1)
			for _, field := range getters {
				if value := field.Get(&test.span); value.Valid() {
					values = append(values, value)
				}
			}
			values = append(values, connectionInfoExtraAttrs(&test.span, &tracker)...)
			attrs := attribute.NewSet(values...)
			client, ok := attrs.Value(attr.Client.OTEL())
			require.True(t, ok)
			assert.Equal(t, "frontend", client.AsString())
			namespace, ok := attrs.Value(attr.ClientNamespace.OTEL())
			require.True(t, ok)
			assert.Equal(t, "shop", namespace.AsString())
			server, ok := attrs.Value(attr.Server.OTEL())
			if test.span.HostName != "" {
				require.True(t, ok)
				assert.Equal(t, test.span.HostName, server.AsString())
				serverNamespace, ok := attrs.Value(attr.ServerNamespace.OTEL())
				require.True(t, ok)
				assert.Equal(t, test.span.OtherNamespace, serverNamespace.AsString())
				if test.name == "raw IP remains a distinct destination" || test.name == "raw IPv6 remains a distinct destination" {
					for _, graphGetter := range fields {
						if graphGetter.ExposedName == string(attr.Server.OTEL()) {
							assert.Equal(t, "outgoing", graphGetter.Get(&test.span).Value.AsString(),
								"the connection-info-specific getter must preserve raw destination identity")
						}
					}
				}
			}
			value, ok := attrs.Value(attr.ConnectionType.OTEL())
			assert.Equal(t, test.wantAttribute, ok)
			if test.wantAttribute {
				assert.Equal(t, test.wantConnType, value.AsString())
			}
		})
	}
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
		File: exec.New(exec.Init{Service: clientID, Pid: clientID.ProcPID}),
	})

	// Send database client spans
	metrics.Send([]request.Span{
		{Service: clientID, Type: request.EventTypeSQLClient, HostName: "postgres-db", Host: "client-host", Method: "SELECT", Path: "users", RequestStart: 100, End: 200},
		{Service: clientID, Type: request.EventTypeRedisClient, HostName: "redis-cache", Host: "client-host", Method: "GET", RequestStart: 150, End: 175},
		{Service: clientID, Type: request.EventTypeKafkaClient, HostName: "kafka-broker", Host: "client-host", Method: request.MessagingPublish, Path: "topic1", RequestStart: 200, End: 250},
		{Service: clientID, Type: request.EventTypeNATSClient, HostName: "nats-broker", Host: "client-host", Method: request.MessagingPublish, Path: "updates.orders", RequestStart: 225, End: 275},
	})

	// Read the exported metrics
	res := readNChan(t, otlp.Records(), 12, timeout)
	assert.NotEmpty(t, res)

	// Check connection_type for each metric
	for _, m := range res {
		connType := m.Attributes["connection_type"]
		server := m.Attributes["server"]

		switch server {
		case "postgres-db", "redis-cache":
			assert.Equal(t, "database", connType, "Database spans should have connection_type=database for server=%s", server)
		case "kafka-broker", "nats-broker":
			assert.Equal(t, "messaging_system", connType, "Messaging spans should have connection_type=messaging_system for server=%s", server)
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
		mcfg, &mpConfig, &attributes.SelectorConfig{}, request.UnresolvedNames{}, input, processEvents)(ctx)
	require.NoError(t, err)

	return otelExporter
}

// The exclusion this replaces dropped the span entirely, which erases an edge where
// every call goes unobserved.
func TestServiceGraphMetrics_UnknownOutcomeIsCountedWithoutADuration(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer otelcfg.RestoreEnvAfterExecution()()

	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))

	otelExporter := makeSvcGraphExporter(ctx, t, otlp, metrics, processEvents)
	go func() {
		otelExporter(ctx)
	}()

	clientID := svc.Attrs{Features: export.FeatureAll, ProcPID: 33, UID: svc.UID{Name: "client", Instance: "the-client"}}

	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Service: clientID, Pid: clientID.ProcPID}),
	})

	// The peer is not instrumented, which is the case the client-side request
	// counter exists for.
	unobserved := request.Span{
		Service: clientID, Type: request.EventTypeHTTPClient,
		Peer: "client-host", Host: "unobserved-peer", HostName: "unobserved-peer",
		Path: "/r", RequestStart: 100, End: 6_000_000_000,
		ResponseObservation: request.ResponseReceived,
	}
	request.SetIgnoreDurations(&unobserved)

	// The control travels the identical path and differs only in having been observed.
	observed := request.Span{
		Service: clientID, Type: request.EventTypeHTTPClient,
		Peer: "client-host", Host: "observed-peer", HostName: "observed-peer",
		Path: "/r", RequestStart: 100, End: 200, Status: 200,
	}

	metrics.Send([]request.Span{unobserved, observed})

	res := readNChan(t, otlp.Records(), 3, timeout)
	// readNChan stops at three and leaves anything further on the channel, so keep
	// reading: a fourth record is the regression the absence assertions below are
	// looking for. The reader re-exports on an interval, so this collects for a fixed
	// window rather than waiting for the channel to fall quiet, which it never does.
	collect := time.After(500 * time.Millisecond)
drain:
	for {
		select {
		case m := <-otlp.Records():
			res = append(res, m)
		case <-collect:
			break drain
		}
	}
	reported := map[string]struct{}{}
	for _, m := range res {
		reported[m.Name+":"+m.Attributes["server"]] = struct{}{}
	}

	// The control proves the edge is drawn at all, so an absent histogram below means
	// the latency was withheld.
	assert.Contains(t, reported, "traces_service_graph_request_client:observed-peer")
	assert.Contains(t, reported, "traces_service_graph_request_total:observed-peer")

	assert.Contains(t, reported, "traces_service_graph_request_total:unobserved-peer",
		"the call happened, so the edge it traveled is counted")
	assert.NotContains(t, reported, "traces_service_graph_request_client:unobserved-peer",
		"its duration is not a measurement, so it lands in no latency histogram")
	assert.NotContains(t, reported, "traces_service_graph_request_failed_total:unobserved-peer",
		"nothing was observed to fail, so it is never counted against the edge")
}

func TestRemoteServiceGraphParticipation(t *testing.T) {
	tracker := NewPidServiceTracker()
	span := request.Span{Type: request.EventTypeHTTPClient, HostName: "backend", OtherNamespace: "shop"}
	require.True(t, ClientSpanToUninstrumentedService(&tracker, &span), "a named peer without graph participation needs a client count")
	require.Equal(t, "virtual_node", ConnectionTypeForSpan(&span, &tracker))
	participating := span
	request.SetIgnoreMetrics(&participating)
	request.SetIgnoreServiceGraphClientCount(&participating)
	require.False(t, ClientSpanToUninstrumentedService(&tracker, &participating))
	require.Empty(t, ConnectionTypeForSpan(&participating, &tracker))
	require.True(t, request.IgnoreMetrics(&participating), "peer participation preserves other span flags")
	require.True(t, ClientSpanToUninstrumentedService(&tracker, &span), "a traces-only peer still needs a client count")
	tracker.AddPID(42, svc.UID{Name: "backend", Namespace: "shop"})
	require.False(t, ClientSpanToUninstrumentedService(&tracker, &span), "local service tracking still suppresses the client count")
	span.HostName = ""
	require.False(t, ClientSpanToUninstrumentedService(&tracker, &span), "an unresolved peer still produces no client count")
}
