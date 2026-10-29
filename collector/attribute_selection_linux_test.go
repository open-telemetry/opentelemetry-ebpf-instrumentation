// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer/consumertest"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestReceiverV2PeerAttributeSelection(t *testing.T) {
	for _, test := range []struct {
		name, selection, hostname string
		wantPeer                  bool
	}{
		{"default", "", "payments-db", false},
		{"include", "{traces: {include: [service.peer.name]}}", "payments-db", true},
		{"exclude", "{traces: {include: [service.peer.name], exclude: [service.peer.name]}}", "payments-db", false},
		{"unknown peer", "{traces: {include: [service.peer.name]}}", "", false},
		{"metric pattern", "{'http.*': {include: ['*']}}", "payments-db", false},
		{"global wildcard", "{'*': {include: ['*']}}", "payments-db", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := "version: '2.0'\n"
			if test.selection != "" {
				input += "attributes:\n  select: " + test.selection + "\n"
			}
			var raw map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(input), &raw))
			cfg := newTestReceiverConfig(t)
			require.NoError(t, confmap.NewFromStringMap(raw).Unmarshal(cfg))
			require.NoError(t, cfg.Validate())

			event := ebpfcommon.SQLRequestTrace{
				Type:            uint8(request.EventTypeSQLClient),
				SubType:         uint8(request.DBPostgres),
				StartMonotimeNs: uint64(time.Second),
				EndMonotimeNs:   uint64(time.Second + 20*time.Millisecond),
			}
			event.Conn.D_port = 5432
			copy(event.Sql[:], "SELECT id FROM users")
			copy(event.Hostname[:], test.hostname)
			event.Tp.TraceId[0] = 1
			event.Tp.SpanId[0] = 1
			span := ebpfcommon.SQLRequestTraceToSpan(&event)
			require.Equal(t, test.hostname, span.HostName)
			span.Service = svc.Attrs{
				UID:      svc.UID{Name: "checkout", Instance: "client"},
				Features: export.FeatureApplicationRED,
			}

			sink := &consumertest.TracesSink{}
			cfg.runtime.Traces.TracesExport = tracesExport(sink)
			ctx, cancel := context.WithCancel(t.Context())
			queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
			run, err := otel.TracesReceiver(
				&global.ContextInfo{Metrics: imetrics.NoopReporter{}},
				cfg.runtime.Traces,
				false,
				&attributes.SelectorConfig{SelectionCfg: cfg.runtime.Attributes.Select},
				queue,
			)(ctx)
			require.NoError(t, err)
			done := make(chan struct{})
			go func() {
				defer close(done)
				run(ctx)
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("trace receiver did not stop")
				}
			})
			queue.Send([]request.Span{span})
			require.Eventually(t, func() bool { return sink.SpanCount() == 1 }, 5*time.Second, 10*time.Millisecond)
			got := sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
			peer, exists := got.Attributes().Get("service.peer.name")
			require.Equal(t, test.wantPeer, exists)
			if exists {
				require.Equal(t, test.hostname, peer.Str())
			}
			port, exists := got.Attributes().Get("server.port")
			require.True(t, exists)
			require.Equal(t, int64(5432), port.Int())
		})
	}
}
