// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	logdata "go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/exceptions"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func exceptionFixture() exceptions.Event {
	modes := services.NewExportModes()
	modes.AllowLogs()
	return exceptions.Event{Service: svc.Attrs{UID: svc.UID{Name: "checkout", Instance: "instance-1"}, Exceptions: services.ExceptionsConfig{Enabled: true}, ExportModes: modes}, Timestamp: time.Unix(100, 200), ObservedTimestamp: time.Unix(101, 0), Type: "ValueError", Message: "invalid item", Stacktrace: "handler:42", TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled}
}

func logsTestConfig() otelcfg.LogsConfig {
	return otelcfg.LogsConfig{BatchMaxSize: 2, QueueSize: 8, BatchTimeout: time.Millisecond}
}

func TestExceptionLogsIndependentOfTraceExport(t *testing.T) {
	e := exceptionFixture()
	unknown := e
	unknown.TraceID = trace.TraceID{}
	unknown.SpanID = trace.SpanID{}
	disabled := e
	disabled.Service.Exceptions.Enabled = false
	blocked := e
	blocked.Service.ExportModes = services.NewExportModes()
	logs := exceptionLogs(&global.ContextInfo{}, []exceptions.Event{e, unknown, disabled, blocked})
	require.Equal(t, 2, logs.LogRecordCount())
	r := logs.ResourceLogs().At(0)
	name, ok := r.Resource().Attributes().Get("service.name")
	require.True(t, ok)
	require.Equal(t, "checkout", name.Str())
	record := r.ScopeLogs().At(0).LogRecords().At(0)
	require.Equal(t, "exception", record.EventName())
	require.Equal(t, e.TraceID.String(), record.TraceID().String())
	require.Equal(t, e.SpanID.String(), record.SpanID().String())
	require.EqualValues(t, e.TraceFlags, record.Flags())
	require.Equal(t, e.Timestamp.UnixNano(), record.Timestamp().AsTime().UnixNano())
	require.Equal(t, e.ObservedTimestamp.UnixNano(), record.ObservedTimestamp().AsTime().UnixNano())
	require.Equal(t, logdata.SeverityNumberUnspecified, record.SeverityNumber())
	for k, want := range map[string]string{"exception.type": e.Type, "exception.message": e.Message, "exception.stacktrace": e.Stacktrace} {
		v, ok := record.Attributes().Get(k)
		require.True(t, ok)
		require.Equal(t, want, v.Str())
	}
	require.True(t, logs.ResourceLogs().At(1).ScopeLogs().At(0).LogRecords().At(0).TraceID().IsEmpty())
}

func TestExceptionLogsSeverity(t *testing.T) {
	for number, text := range map[int32]string{17: "ERROR", 21: "FATAL", 22: "FATAL2"} {
		e := exceptionFixture()
		e.SeverityNumber = number
		record := exceptionLogs(&global.ContextInfo{}, []exceptions.Event{e}).ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		require.EqualValues(t, number, record.SeverityNumber())
		require.Equal(t, text, record.SeverityText())
	}
}

func TestExceptionLogsNoSpanContextWhenAppExportsTraces(t *testing.T) {
	e := exceptionFixture()
	e.Service.SetExportsOTelTraces()
	record := exceptionLogs(&global.ContextInfo{}, []exceptions.Event{e}).ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	require.True(t, record.TraceID().IsEmpty())
	require.True(t, record.SpanID().IsEmpty())
	v, ok := record.Attributes().Get("exception.type")
	require.True(t, ok)
	require.Equal(t, e.Type, v.Str())
}

func TestExceptionLogsOTLPHTTP(t *testing.T) {
	for _, compression := range []string{"none", "gzip"} {
		t.Run(compression, func(t *testing.T) {
			received := make(chan logdata.Logs, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/custom/logs", r.URL.Path)
				assert.Equal(t, "test", r.Header.Get("X-Exception-Test"))
				var body io.Reader = r.Body
				if compression == "gzip" {
					assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
					reader, err := gzip.NewReader(r.Body)
					if !assert.NoError(t, err) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					defer reader.Close()
					body = reader
				} else {
					assert.Empty(t, r.Header.Get("Content-Encoding"))
				}
				payload, err := io.ReadAll(body)
				if !assert.NoError(t, err) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				req := plogotlp.NewExportRequest()
				assert.Equal(t, "application/x-protobuf", r.Header.Get("Content-Type"))
				err = req.UnmarshalProto(payload)
				w.Header().Set("Content-Type", "application/x-protobuf")
				if !assert.NoError(t, err) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				received <- req.Logs()
			}))
			defer server.Close()
			cfg := logsTestConfig()
			cfg.Endpoint = server.URL + "/custom/logs"
			cfg.Protocol = otelcfg.ProtocolHTTPProtobuf
			cfg.Compression = compression
			cfg.InjectHeaders = func(h map[string]string) { h["X-Exception-Test"] = "test" }
			send, closeSender, err := newTestLogsSender(t, cfg)
			require.NoError(t, err)
			require.NoError(t, send(t.Context(), exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture()})))
			require.NoError(t, closeSender())
			select {
			case got := <-received:
				require.Equal(t, 1, got.LogRecordCount())
				record := got.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				require.Equal(t, exceptionFixture().TraceID.String(), record.TraceID().String())
				require.Equal(t, exceptionFixture().SpanID.String(), record.SpanID().String())
				require.EqualValues(t, trace.FlagsSampled, record.Flags())
			case <-time.After(5 * time.Second):
				t.Fatal("no OTLP logs received")
			}
		})
	}
}

func TestExceptionLogsHTTPResponse(t *testing.T) {
	for _, protocol := range []otelcfg.Protocol{otelcfg.ProtocolHTTPProtobuf} {
		for _, tc := range []struct {
			name      string
			rejected  int64
			message   string
			malformed bool
			wantError string
		}{
			{name: "success"},
			{name: "rejected records", rejected: 1, message: "invalid record", wantError: "invalid record"},
			{name: "rejection without message", rejected: 1, wantError: "1 logs rejected"},
			{name: "warning", message: "collector warning", wantError: "collector warning"},
			{name: "malformed response", malformed: true, wantError: "cannot parse invalid wire-format data"},
		} {
			t.Run(string(protocol)+"/"+tc.name, func(t *testing.T) {
				response := plogotlp.NewExportResponse()
				response.PartialSuccess().SetRejectedLogRecords(tc.rejected)
				response.PartialSuccess().SetErrorMessage(tc.message)
				body, err := response.MarshalProto()
				require.NoError(t, err)
				if tc.malformed {
					body = []byte{0xff}
				}
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.Header().Set("Content-Type", "application/x-protobuf")
					_, _ = w.Write(body)
				}))
				defer server.Close()
				cfg := logsTestConfig()
				cfg.Endpoint = server.URL + "/v1/logs"
				cfg.Protocol = protocol
				send, closeSender, err := newTestLogsSender(t, cfg)
				require.NoError(t, err)
				defer func() { require.NoError(t, closeSender()) }()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				err = send(ctx, exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture(), exceptionFixture()}))
				if tc.wantError == "" {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, tc.wantError)
				}
				require.EqualValues(t, 1, requests.Load(), "successful HTTP responses must not trigger retries")
			})
		}
	}
}

type exceptionGRPCServer struct {
	plogotlp.UnimplementedGRPCServer
	received  chan logdata.Logs
	rejected  int64
	message   string
	requests  atomic.Int32
	retryOnce bool
}

func (s *exceptionGRPCServer) Export(_ context.Context, r plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	if s.requests.Add(1) == 1 && s.retryOnce {
		st, err := status.New(codes.ResourceExhausted, "busy").WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(logsRequestTimeout + time.Second)})
		if err != nil {
			return plogotlp.NewExportResponse(), err
		}
		return plogotlp.NewExportResponse(), st.Err()
	}
	if s.received != nil {
		s.received <- r.Logs()
	}
	response := plogotlp.NewExportResponse()
	if s.rejected > 0 || s.message != "" {
		response.PartialSuccess().SetRejectedLogRecords(s.rejected)
		response.PartialSuccess().SetErrorMessage(s.message)
	}
	return response, nil
}

func TestExceptionLogsOTLPGRPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	defer server.Stop()
	sink := &exceptionGRPCServer{received: make(chan logdata.Logs, 1)}
	plogotlp.RegisterGRPCServer(server, sink)
	go func() { _ = server.Serve(listener) }()
	cfg := logsTestConfig()
	cfg.Endpoint = "http://" + listener.Addr().String()
	cfg.Protocol = otelcfg.ProtocolGRPC
	send, closeSender, err := newTestLogsSender(t, cfg)
	require.NoError(t, err)
	require.NoError(t, send(t.Context(), exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture()})))
	require.NoError(t, closeSender())
	select {
	case got := <-sink.received:
		require.Equal(t, 1, got.LogRecordCount())
		record := got.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		require.Equal(t, exceptionFixture().TraceID.String(), record.TraceID().String())
		require.Equal(t, exceptionFixture().SpanID.String(), record.SpanID().String())
		require.EqualValues(t, trace.FlagsSampled, record.Flags())
	case <-time.After(5 * time.Second):
		t.Fatal("no OTLP logs received")
	}
}

func TestExceptionLogsGRPCResponse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rejected  int64
		message   string
		wantError string
	}{
		{name: "success"},
		{name: "rejected records", rejected: 1, message: "invalid record", wantError: "invalid record"},
		{name: "rejection without message", rejected: 1, wantError: "1 logs rejected"},
		{name: "warning", message: "collector warning", wantError: "collector warning"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			server := grpc.NewServer()
			defer server.Stop()
			sink := &exceptionGRPCServer{rejected: tc.rejected, message: tc.message}
			plogotlp.RegisterGRPCServer(server, sink)
			go func() { _ = server.Serve(listener) }()
			cfg := logsTestConfig()
			cfg.Endpoint = "http://" + listener.Addr().String()
			cfg.Protocol = otelcfg.ProtocolGRPC
			send, closeSender, err := newTestLogsSender(t, cfg)
			require.NoError(t, err)
			defer func() { require.NoError(t, closeSender()) }()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err = send(ctx, exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture(), exceptionFixture()}))
			if tc.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantError)
			}
			require.EqualValues(t, 1, sink.requests.Load(), "successful gRPC responses must not trigger retries")
		})
	}
}

func TestExceptionLogsReceiver(t *testing.T) {
	received := make(chan logdata.Logs, 1)
	cfg := logsTestConfig()
	cfg.LogsExport = func(_ context.Context, l logdata.Logs) error { received <- l; return nil }
	input := msg.NewQueue[[]exceptions.Event]()
	run, err := ExceptionLogsReceiver(&global.ContextInfo{}, cfg, nil, input)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); run(ctx) }()
	input.Send([]exceptions.Event{exceptionFixture()})
	select {
	case got := <-received:
		require.Equal(t, 1, got.LogRecordCount())
		record := got.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		require.Equal(t, exceptionFixture().TraceID.String(), record.TraceID().String())
		require.Equal(t, exceptionFixture().SpanID.String(), record.SpanID().String())
		require.EqualValues(t, trace.FlagsSampled, record.Flags())
	case <-time.After(5 * time.Second):
		t.Fatal("logs export received nothing")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not shut down")
	}
}

func TestExceptionLogsReceiverShutdownTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		defer close(release)
		cfg := logsTestConfig()
		cfg.BatchMaxSize = 1
		cfg.LogsExport = func(_ context.Context, _ logdata.Logs) error {
			close(entered)
			<-release
			return nil
		}
		input := msg.NewQueue[[]exceptions.Event]()
		run, err := ExceptionLogsReceiver(&global.ContextInfo{}, cfg, nil, input)(t.Context())
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); run(ctx) }()
		input.Send([]exceptions.Event{exceptionFixture()})
		<-entered
		cancel()
		synctest.Wait()
		time.Sleep(logsShutdownTimeout)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("receiver waited for a blocked consumer after the shutdown timeout")
		}
	})
}

func TestExceptionLogsReceiverResourceSelection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selection attributes.Selection
		removed   []string
	}{
		{name: "default preserves resources"},
		{
			name: "exclude all resource sources",
			selection: attributes.Selection{"resource": attributes.InclusionLists{
				Exclude: []string{"cloud.account.id", "deployment.environment", "extra.private"},
			}},
			removed: []string{"cloud.account.id", "deployment.environment", "extra.private"},
		},
		{
			name: "include with explicit exclusion",
			selection: attributes.Selection{"resource": attributes.InclusionLists{
				Include: []string{"service.name", "cloud.*", "deployment.*", "extra.*"},
				Exclude: []string{"cloud.account.id"},
			}},
			removed: []string{"cloud.account.id", "k8s.pod.name"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := exceptionFixture()
			e.Service.Metadata = map[attr.Name]string{
				"cloud.account.id": "account-1",
				"cloud.region":     "eu-central-1",
				"k8s.pod.name":     "checkout-1",
			}
			e.Service.EnvVars = map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "deployment.environment=prod"}
			info := &global.ContextInfo{ExtraResourceAttributes: []attribute.KeyValue{
				attribute.String("extra.private", "private-value"),
				attribute.String("extra.public", "public-value"),
			}}
			received := make(chan logdata.Logs, 1)
			cfg := logsTestConfig()
			cfg.LogsExport = func(_ context.Context, logs logdata.Logs) error { received <- logs; return nil }
			input := msg.NewQueue[[]exceptions.Event]()
			tc.selection.Normalize()
			run, err := ExceptionLogsReceiver(info, cfg, tc.selection, input)(t.Context())
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); run(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("receiver did not shut down")
				}
			})
			input.Send([]exceptions.Event{e})
			select {
			case logs := <-received:
				require.Equal(t, 1, logs.LogRecordCount())
				resource := logs.ResourceLogs().At(0)
				want := map[string]string{
					"service.name":           "checkout",
					"cloud.account.id":       "account-1",
					"cloud.region":           "eu-central-1",
					"k8s.pod.name":           "checkout-1",
					"deployment.environment": "prod",
					"extra.private":          "private-value",
					"extra.public":           "public-value",
				}
				for _, key := range tc.removed {
					delete(want, key)
					_, ok := resource.Resource().Attributes().Get(key)
					assert.False(t, ok, key)
				}
				for key, value := range want {
					got, ok := resource.Resource().Attributes().Get(key)
					assert.True(t, ok, key)
					assert.Equal(t, value, got.Str(), key)
				}
				record := resource.ScopeLogs().At(0).LogRecords().At(0)
				message, ok := record.Attributes().Get("exception.message")
				require.True(t, ok)
				require.Equal(t, e.Message, message.Str())
			case <-time.After(5 * time.Second):
				t.Fatal("logs export received nothing")
			}
		})
	}
}

func TestExceptionLogsHTTPPermanentError(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	cfg := logsTestConfig()
	cfg.Endpoint = server.URL + "/v1/logs"
	cfg.Protocol = otelcfg.ProtocolHTTPProtobuf
	send, closeSender, err := newTestLogsSender(t, cfg)
	require.NoError(t, err)
	require.ErrorContains(t, send(t.Context(), exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture()})), "400 Bad Request")
	require.NoError(t, closeSender())
	require.Equal(t, 1, requests)
}

func TestExceptionLogsDebugStdout(t *testing.T) {
	const child = "OBI_TEST_EXCEPTION_STDOUT"
	if os.Getenv(child) != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestExceptionLogsDebugStdout$")
		cmd.Env = append(os.Environ(), child+"=1")
		output, err := cmd.Output()
		require.NoError(t, err)
		text := string(output)
		require.Contains(t, text, `"invalid item"`)
		require.Contains(t, text, exceptionFixture().TraceID.String())
		require.Contains(t, text, exceptionFixture().SpanID.String())
		return
	}
	cfg := logsTestConfig()
	cfg.Protocol = otelcfg.ProtocolDebug
	require.True(t, cfg.Enabled())
	send, closeSender, err := newTestLogsSender(t, cfg)
	require.NoError(t, err)
	require.NoError(t, send(t.Context(), exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture()})))
	require.NoError(t, closeSender())
}

func TestExceptionLogsUnixSocket(t *testing.T) {
	for _, protocol := range []otelcfg.Protocol{otelcfg.ProtocolHTTPProtobuf, otelcfg.ProtocolGRPC} {
		t.Run(string(protocol), func(t *testing.T) {
			dir := t.TempDir()
			socket := filepath.Join(dir, "otlp.sock")
			listener, err := net.Listen("unix", socket)
			require.NoError(t, err)
			received := make(chan logdata.Logs, 1)
			if protocol == otelcfg.ProtocolGRPC {
				server := grpc.NewServer()
				defer server.Stop()
				plogotlp.RegisterGRPCServer(server, &exceptionGRPCServer{received: received})
				go func() { _ = server.Serve(listener) }()
			} else {
				server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					data, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					req := plogotlp.NewExportRequest()
					if err := req.UnmarshalProto(data); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					received <- req.Logs()
				})}
				defer server.Close()
				go func() { _ = server.Serve(listener) }()
			}
			cfg := logsTestConfig()
			cfg.Endpoint = "unix://" + socket
			cfg.Protocol = protocol
			send, closeSender, err := newTestLogsSender(t, cfg)
			require.NoError(t, err)
			require.NoError(t, send(t.Context(), exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture()})))
			require.NoError(t, closeSender())
			select {
			case got := <-received:
				record := got.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				require.Equal(t, exceptionFixture().TraceID.String(), record.TraceID().String())
				require.Equal(t, exceptionFixture().SpanID.String(), record.SpanID().String())
			case <-time.After(5 * time.Second):
				t.Fatal("no logs over Unix socket")
			}
		})
	}
}

// Exercise the same SDK record construction for transport and field assertions.
type captureLogsExporter struct {
	records []sdklog.Record
}

func (e *captureLogsExporter) Export(_ context.Context, records []sdklog.Record) error {
	for i := range records {
		e.records = append(e.records, records[i].Clone())
	}
	return nil
}
func (*captureLogsExporter) Shutdown(context.Context) error   { return nil }
func (*captureLogsExporter) ForceFlush(context.Context) error { return nil }

func exceptionRecords(info *global.ContextInfo, events []exceptions.Event) []sdklog.Record {
	exporter := &captureLogsExporter{}
	emitter := newExceptionLogEmitter(sdklog.NewSimpleProcessor(exporter))
	for i := range events {
		emitter.emit(context.Background(), info, nil, &events[i])
	}
	return exporter.records
}

func exceptionLogs(info *global.ContextInfo, events []exceptions.Event) logdata.Logs {
	var logs logdata.Logs
	exporter := consumerLogsExporter{send: func(_ context.Context, l logdata.Logs) error { logs = l; return nil }}
	_ = exporter.Export(context.Background(), exceptionRecords(info, events))
	return logs
}

func newTestLogsSender(t *testing.T, cfg otelcfg.LogsConfig) (func(context.Context, []sdklog.Record) error, func() error, error) {
	t.Helper()
	exporter, err := newLogsExporter(t.Context(), cfg)
	if err != nil {
		return nil, nil, err
	}
	return exporter.Export, func() error { return exporter.Shutdown(t.Context()) }, nil
}

func TestExceptionLogResourcesAndEviction(t *testing.T) {
	exporter := &captureLogsExporter{}
	processor := sdklog.NewSimpleProcessor(exporter)
	emitter := newExceptionLogEmitter(processor)
	info := &global.ContextInfo{}
	event := exceptionFixture()
	emitter.emit(t.Context(), info, nil, &event)
	event.Service.Metadata = map[attr.Name]string{"k8s.pod.name": "new-pod"}
	emitter.emit(t.Context(), info, nil, &event)
	require.Equal(t, 2, emitter.loggers.Len(), "resource changes must create a new logger")
	for i := range logsLoggerCacheSize {
		event.Service.UID.Instance = fmt.Sprintf("instance-%d", i)
		emitter.emit(t.Context(), info, nil, &event)
	}
	event = exceptionFixture()
	emitter.emit(t.Context(), info, nil, &event)
	require.Equal(t, logsLoggerCacheSize, emitter.loggers.Len())
	require.Len(t, exporter.records, logsLoggerCacheSize+3, "evicting a logger must not shut down the shared processor")
	require.Equal(t, exporter.records[0].Resource(), exporter.records[len(exporter.records)-1].Resource())
	_, ok := exporter.records[0].Resource().Set().Value(attribute.Key("k8s.pod.name"))
	require.False(t, ok, "later metadata changes must not affect queued records")
	pod, ok := exporter.records[1].Resource().Set().Value(attribute.Key("k8s.pod.name"))
	require.True(t, ok)
	require.Equal(t, "new-pod", pod.AsString())
}

func TestExceptionLogsGRPCRetryInfo(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	defer server.Stop()
	sink := &exceptionGRPCServer{retryOnce: true, received: make(chan logdata.Logs, 1)}
	plogotlp.RegisterGRPCServer(server, sink)
	go func() { _ = server.Serve(listener) }()
	cfg := logsTestConfig()
	cfg.Endpoint = "http://" + listener.Addr().String()
	cfg.Protocol = otelcfg.ProtocolGRPC
	send, closeSender, err := newTestLogsSender(t, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, closeSender()) }()
	require.NoError(t, send(t.Context(), exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture()})))
	require.EqualValues(t, 2, sink.requests.Load())
	require.Equal(t, 1, (<-sink.received).LogRecordCount())
}

func TestExceptionLogsReceiverFlushesOnShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := logsTestConfig()
		cfg.BatchTimeout = time.Hour
		received := make(chan logdata.Logs, 2)
		cfg.LogsExport = func(_ context.Context, logs logdata.Logs) error { received <- logs; return nil }
		input := msg.NewQueue[[]exceptions.Event]()
		run, err := ExceptionLogsReceiver(&global.ContextInfo{}, cfg, nil, input)(t.Context())
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); run(ctx) }()
		first := exceptionFixture()
		second := first
		second.Service.UID.Name = "payments"
		input.Send([]exceptions.Event{first, second})
		synctest.Wait()
		require.Len(t, received, 1, "a full batch should export before the timer")
		batch := <-received
		require.Equal(t, 2, batch.LogRecordCount())
		for i, name := range []string{"checkout", "payments"} {
			got, ok := batch.ResourceLogs().At(i).Resource().Attributes().Get("service.name")
			require.True(t, ok)
			require.Equal(t, name, got.Str())
		}
		input.Send([]exceptions.Event{first})
		synctest.Wait()
		require.Empty(t, received, "partial batch should remain queued")
		cancel()
		<-done
		require.Len(t, received, 1)
		require.Equal(t, 1, (<-received).LogRecordCount())
	})
}

func TestExceptionLogsUnsetCaptureTimestamp(t *testing.T) {
	event := exceptionFixture()
	event.Timestamp = time.Time{}
	event.ObservedTimestamp = time.Time{}
	logs := exceptionLogs(&global.ContextInfo{}, []exceptions.Event{event})
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	require.Zero(t, record.Timestamp())
	require.NotZero(t, record.ObservedTimestamp())
}

func TestExceptionLogsReceiverDropsWhenFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := logsTestConfig()
		cfg.BatchMaxSize = 1
		cfg.QueueSize = 2
		entered := make(chan struct{})
		release := make(chan struct{})
		var exported atomic.Int32
		cfg.LogsExport = func(_ context.Context, logs logdata.Logs) error {
			if exported.Add(int32(logs.LogRecordCount())) == 1 {
				close(entered)
				<-release
			}
			return nil
		}
		input := msg.NewQueue[[]exceptions.Event]()
		run, err := ExceptionLogsReceiver(&global.ContextInfo{}, cfg, nil, input)(t.Context())
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); run(ctx) }()
		input.Send([]exceptions.Event{exceptionFixture()})
		<-entered
		input.Send([]exceptions.Event{exceptionFixture(), exceptionFixture(), exceptionFixture(), exceptionFixture()})
		synctest.Wait()
		// The receiver can consume another batch while export is blocked and
		// the SDK queue is full.
		input.Send([]exceptions.Event{exceptionFixture()})
		synctest.Wait()
		close(release)
		cancel()
		<-done
		require.EqualValues(t, 1+cfg.QueueSize, exported.Load())
	})
}

func TestExceptionLogsReceiverCancelsExportAfterShutdownTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := logsTestConfig()
		cfg.BatchMaxSize = 1
		entered := make(chan struct{})
		canceled := make(chan struct{})
		cfg.LogsExport = func(ctx context.Context, _ logdata.Logs) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			return ctx.Err()
		}
		input := msg.NewQueue[[]exceptions.Event]()
		run, err := ExceptionLogsReceiver(&global.ContextInfo{}, cfg, nil, input)(t.Context())
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); run(ctx) }()
		input.Send([]exceptions.Event{exceptionFixture()})
		<-entered
		cancel()
		synctest.Wait()
		select {
		case <-canceled:
			t.Fatal("export canceled before the drain deadline")
		default:
		}
		time.Sleep(logsShutdownTimeout)
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Fatal("in-flight export was not canceled")
		}
		<-done
	})
}
