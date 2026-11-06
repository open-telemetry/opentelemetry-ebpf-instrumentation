// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestReceiverHTTPQueryParameterRedaction(t *testing.T) {
	const query = "token=default-secret&customer_secret=private&customer_secr%65t=encoded&customer_secret=repeated&Customer_secret=case&page=2"
	for _, test := range []struct {
		name, http, want string
	}{
		{name: "defaults", http: "{}", want: strings.Replace(query, "default-secret", "REDACTED", 1)},
		{name: "null", http: "{query_parameters: {redaction: null}}", want: strings.Replace(query, "default-secret", "REDACTED", 1)},
		{name: "replacement", http: "{query_parameters: {redaction: {names: [customer_secret]}}}", want: "token=default-secret&customer_secret=REDACTED&customer_secr%65t=REDACTED&customer_secret=REDACTED&Customer_secret=case&page=2"},
		{name: "empty", http: "{query_parameters: {redaction: {names: []}}}", want: query},
		{name: "empty policy", http: "{query_parameters: {redaction: {}}}", want: strings.Replace(query, "default-secret", "REDACTED", 1)},
		{name: "replacement only", http: "{query_parameters: {redaction: {replacement: hidden}}}", want: strings.Replace(query, "default-secret", "hidden", 1)},
		{name: "custom replacement", http: "{query_parameters: {redaction: {names: [customer_secret], replacement: '[hidden] &='}}}", want: "token=default-secret&customer_secret=%5Bhidden%5D+%26%3D&customer_secr%65t=%5Bhidden%5D+%26%3D&customer_secret=%5Bhidden%5D+%26%3D&Customer_secret=case&page=2"},
		{name: "empty replacement", http: "{query_parameters: {redaction: {names: [customer_secret], replacement: ''}}}", want: "token=default-secret&customer_secret=&customer_secr%65t=&customer_secret=&Customer_secret=case&page=2"},
		{name: "null replacement", http: "{query_parameters: {redaction: {names: [token], replacement: null}}}", want: strings.Replace(query, "default-secret", "REDACTED", 1)},
		{name: "disabled custom policy", http: "{query_parameters: {redaction: {names: [], replacement: hidden}}}", want: query},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := "version: '2.0'\ninstrumentation: {http: " + test.http + "}\n"
			var raw map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(input), &raw))
			cfg := newTestReceiverConfig(t)
			require.NoError(t, confmap.NewFromStringMap(raw).Unmarshal(cfg))
			require.NoError(t, cfg.Validate())

			sink := &consumertest.TracesSink{}
			cfg.runtime.Traces.TracesExport = tracesExport(sink)
			ctx, cancel := context.WithCancel(t.Context())
			queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
			run, err := otel.TracesReceiver(
				&global.ContextInfo{Metrics: imetrics.NoopReporter{}},
				cfg.runtime.Traces, false,
				&attributes.SelectorConfig{
					SelectionCfg:            cfg.runtime.Attributes.Select,
					SensitiveQueryParamsCfg: cfg.runtime.Attributes.SensitiveQueryParams,
				}, queue,
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

			spans := []request.Span{}
			for i, kind := range []request.EventType{request.EventTypeHTTP, request.EventTypeHTTPClient} {
				spans = append(spans, request.Span{
					Type: kind, Method: "GET", Path: "/orders", FullPath: "/orders?" + query,
					Host: "example.com", HostPort: 80, Status: 200,
					RequestStart: int64(time.Second), Start: int64(time.Second), End: int64(2 * time.Second),
					TraceID: trace.TraceID{1}, SpanID: trace.SpanID{byte(i + 1)},
					Service: svc.Attrs{UID: svc.UID{Name: "query-redaction", Instance: "test"}},
				})
			}
			queue.Send(spans)
			require.Eventually(t, func() bool { return sink.SpanCount() == 2 }, 5*time.Second, 10*time.Millisecond)
			var clients, servers int
			for _, td := range sink.AllTraces() {
				for _, rs := range td.ResourceSpans().All() {
					for _, scope := range rs.ScopeSpans().All() {
						for _, span := range scope.Spans().All() {
							switch span.Kind() {
							case ptrace.SpanKindClient:
								clients++
								full, ok := span.Attributes().Get("url.full")
								require.True(t, ok)
								_, got, ok := strings.Cut(full.Str(), "?")
								require.True(t, ok)
								require.Equal(t, test.want, got)
							case ptrace.SpanKindServer:
								servers++
								value, ok := span.Attributes().Get("url.query")
								require.True(t, ok)
								require.Equal(t, test.want, value.Str())
							}
						}
					}
				}
			}
			require.Equal(t, 1, clients)
			require.Equal(t, 1, servers)
		})
	}
}
