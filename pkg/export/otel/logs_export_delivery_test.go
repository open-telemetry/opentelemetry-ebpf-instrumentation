// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	collectorplog "go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

const testLogsEventName = "obi.otlp.delivery.test"

func oneLogRecord() collectorplog.Logs {
	logs := collectorplog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "otlp-delivery-test")
	lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.SetEventName(testLogsEventName)
	lr.Body().SetStr("hello")
	return logs
}

type otlpLogsGRPCServer struct {
	plogotlp.UnimplementedGRPCServer
	mu       sync.Mutex
	received []collectorplog.Logs
}

func (s *otlpLogsGRPCServer) Export(_ context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	s.mu.Lock()
	s.received = append(s.received, req.Logs())
	s.mu.Unlock()
	return plogotlp.NewExportResponse(), nil
}

func (s *otlpLogsGRPCServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.received)
}

func (s *otlpLogsGRPCServer) first() collectorplog.Logs {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received[0]
}

// startOTLPLogsGRPCServer starts an in-process OTLP/gRPC logs receiver that
// accepts every export, returning its "http://host:port" endpoint.
func startOTLPLogsGRPCServer(t *testing.T) (string, *otlpLogsGRPCServer) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	logsSrv := &otlpLogsGRPCServer{}
	plogotlp.RegisterGRPCServer(srv, logsSrv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "http://" + lis.Addr().String(), logsSrv
}

// TestLogsExportDelivery proves a log record pushed through getLogsExporter
// actually crosses the real OTLP wire (HTTP and gRPC) and is decodable by a
// real OTLP logs receiver on the other end, unlike the internal
// TestSuite_QueueProcessingLogs integration test, which only exercises the
// in-process debug exporter and never puts a byte on the wire.
func TestLogsExportDelivery(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		var mu sync.Mutex
		var received []collectorplog.Logs
		coll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			req := plogotlp.NewExportRequest()
			if err := req.UnmarshalProto(body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			received = append(received, req.Logs())
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		defer coll.Close()

		cfg := otelcfg.LogsConfig{CommonEndpoint: coll.URL}
		exp, host, err := getLogsExporter(context.Background(), cfg)
		require.NoError(t, err)
		require.NoError(t, exp.Start(context.Background(), host))
		t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

		require.NoError(t, exp.ConsumeLogs(context.Background(), oneLogRecord()))

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(received) > 0
		}, 5*time.Second, 20*time.Millisecond, "log record must be delivered to the OTLP HTTP receiver")

		mu.Lock()
		lr := received[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		mu.Unlock()
		assert.Equal(t, testLogsEventName, lr.EventName(), "the exact log record content must survive the real OTLP HTTP round trip")
	})

	t.Run("gRPC", func(t *testing.T) {
		endpoint, srv := startOTLPLogsGRPCServer(t)
		cfg := otelcfg.LogsConfig{CommonEndpoint: endpoint, Protocol: otelcfg.ProtocolGRPC}
		exp, host, err := getLogsExporter(context.Background(), cfg)
		require.NoError(t, err)
		require.NoError(t, exp.Start(context.Background(), host))
		t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

		require.NoError(t, exp.ConsumeLogs(context.Background(), oneLogRecord()))

		require.Eventually(t, func() bool { return srv.count() > 0 }, 5*time.Second, 20*time.Millisecond,
			"log record must be delivered to the OTLP gRPC receiver")

		lr := srv.first().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		assert.Equal(t, testLogsEventName, lr.EventName(), "the exact log record content must survive the real OTLP gRPC round trip")
	})
}
