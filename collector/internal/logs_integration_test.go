// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pipeline"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/collector"
	"go.opentelemetry.io/obi/collector/internal"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/exceptions"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestCollectorReceiverExportsExceptionLogs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		signals []pipeline.Signal
	}{
		{name: "logs only", signals: []pipeline.Signal{pipeline.SignalLogs}},
		{name: "logs first", signals: []pipeline.Signal{pipeline.SignalLogs, pipeline.SignalTraces, pipeline.SignalMetrics}},
		{name: "logs last", signals: []pipeline.Signal{pipeline.SignalMetrics, pipeline.SignalTraces, pipeline.SignalLogs}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var runs atomic.Int32
			stopped := make(chan struct{})
			runContexts := make(chan context.Context, 1)
			captured := time.Unix(100, 200)
			internal.SetRunOBIForTest(t, func(ctx context.Context, cfg *obi.Config, info *global.ContextInfo, _ *instrumentations.InstrumentationSelection, _ ...instrumenter.Option) error {
				runs.Add(1)
				runContexts <- ctx
				defer close(stopped)
				input := msg.NewQueue[[]exceptions.Event]()
				run, err := otel.ExceptionLogsReceiver(info, cfg.Logs, cfg.Attributes.Select, input)(ctx)
				if err != nil {
					return err
				}
				modes := services.NewExportModes()
				modes.AllowLogs()
				input.Send([]exceptions.Event{{
					Service: svc.Attrs{
						UID:        svc.UID{Name: "checkout", Instance: "checkout-1"},
						Exceptions: cfg.Exceptions, ExportModes: modes,
					},
					Timestamp: captured, ObservedTimestamp: captured.Add(time.Second),
					Type: "ValueError", Message: "invalid item", Stacktrace: "handler:42",
					TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
				}})
				input.Close()
				run(ctx)
				<-ctx.Done()
				return nil
			})

			factory := collector.NewFactory()
			settings := receivertest.NewNopSettings(factory.Type())
			settings.ID = component.MustNewIDWithName("obi", tc.name)
			sink := &consumertest.LogsSink{}
			var receivers []component.Component
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				for _, receiver := range receivers {
					require.NoError(t, receiver.Shutdown(ctx))
				}
			})
			for _, signal := range tc.signals {
				var receiver component.Component
				var err error
				switch signal {
				case pipeline.SignalLogs:
					receiver, err = factory.CreateLogs(t.Context(), settings, exceptionReceiverConfig(), sink)
				case pipeline.SignalTraces:
					receiver, err = factory.CreateTraces(t.Context(), settings, exceptionReceiverConfig(), consumertest.NewNop())
				case pipeline.SignalMetrics:
					receiver, err = factory.CreateMetrics(t.Context(), settings, exceptionReceiverConfig(), consumertest.NewNop())
				}
				require.NoError(t, err)
				receivers = append(receivers, receiver)
			}
			for _, receiver := range receivers {
				require.NoError(t, receiver.Start(t.Context(), componenttest.NewNopHost()))
			}
			require.Eventually(t, func() bool { return sink.LogRecordCount() == 1 }, 5*time.Second, time.Millisecond)
			require.EqualValues(t, 1, runs.Load(), "signals must share one OBI instance")
			runContext := <-runContexts
			logs := sink.AllLogs()[0]
			resource := logs.ResourceLogs().At(0)
			name, ok := resource.Resource().Attributes().Get("service.name")
			require.True(t, ok)
			require.Equal(t, "checkout", name.Str())
			record := resource.ScopeLogs().At(0).LogRecords().At(0)
			require.Equal(t, "exception", record.EventName())
			require.Equal(t, captured.UnixNano(), record.Timestamp().AsTime().UnixNano())
			require.Equal(t, captured.Add(time.Second).UnixNano(), record.ObservedTimestamp().AsTime().UnixNano())
			require.Equal(t, trace.TraceID{1}.String(), record.TraceID().String())
			require.Equal(t, trace.SpanID{2}.String(), record.SpanID().String())
			require.EqualValues(t, trace.FlagsSampled, record.Flags())
			for key, want := range map[string]string{"exception.type": "ValueError", "exception.message": "invalid item", "exception.stacktrace": "handler:42"} {
				got, ok := record.Attributes().Get(key)
				require.True(t, ok)
				require.Equal(t, want, got.Str())
			}
			for i, receiver := range receivers {
				require.NoError(t, receiver.Shutdown(t.Context()))
				if i < len(receivers)-1 {
					require.NoError(t, runContext.Err(), "OBI must run until the last signal receiver stops")
				}
			}
			select {
			case <-stopped:
			default:
				t.Fatal("last receiver shutdown did not stop OBI")
			}
		})
	}
}

func exceptionReceiverConfig() *obi.Config {
	cfg := obi.DefaultConfig
	cfg.Exceptions.Enabled = true
	cfg.Logs.BatchMaxSize = 1
	cfg.Attributes.HostID.Override = "test-host-id"
	cfg.Attributes.MetadataRetry = metadata.RetryConfig{Timeout: time.Millisecond}
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledFalse
	// Separate configs include validation placeholders, as receiver configs do.
	// Creating another signal must not replace an already registered consumer.
	cfg.Traces.TracesExport = func(context.Context, ptrace.Traces) error { return nil }
	cfg.OTELMetrics.MetricsExport = func(context.Context, pmetric.Metrics) error { return nil }
	cfg.Logs.LogsExport = func(context.Context, plog.Logs) error { return nil }
	return &cfg
}
