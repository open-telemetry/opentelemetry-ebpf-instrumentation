// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert_test

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestStandaloneHTTPQueryParameterRedactionExport(t *testing.T) {
	const query = "token=default-secret&customer_secret=private&customer_secr%65t=encoded&customer_secret=repeated&Customer_secret=case&page=2"
	const customQuery = "token=default-secret&customer_secret=REDACTED&customer_secr%65t=REDACTED&customer_secret=REDACTED&Customer_secret=case&page=2"

	for _, test := range []struct {
		name, http, want string
		excludeQuery     bool
	}{
		{name: "defaults", http: "{}", want: strings.Replace(query, "default-secret", "REDACTED", 1)},
		{name: "null", http: "{query_parameters: {redaction: null}}", want: strings.Replace(query, "default-secret", "REDACTED", 1)},
		{name: "replacement", http: "{query_parameters: {redaction: [customer_secret]}}", want: customQuery},
		{name: "empty", http: "{query_parameters: {redaction: []}}", want: query},
		{name: "excluded query", http: "{query_parameters: {redaction: [customer_secret]}}", want: customQuery, excludeQuery: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			exported := make(chan ptrace.Traces, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var reader io.Reader = r.Body
				if r.Header.Get("Content-Encoding") == "gzip" {
					decoded, err := gzip.NewReader(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					defer decoded.Close()
					reader = decoded
				}
				body, err := io.ReadAll(reader)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				decoder := ptrace.ProtoUnmarshaler{}
				td, err := decoder.UnmarshalTraces(body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				exported <- td
				w.Header().Set("Content-Type", "application/x-protobuf")
			}))
			defer server.Close()

			input := fmt.Sprintf("file_format: '1.0'\ntracer_provider:\n  processors:\n    - batch:\n        schedule_delay: 10\n        exporter:\n          otlp_http:\n            endpoint: %s/v1/traces\nextensions:\n  obi:\n    version: '2.0'\n    capture:\n      instrumentation:\n        http: %s\n", server.URL, test.http)
			if test.excludeQuery {
				input += "      attributes: {select: {traces: {exclude: [url.query]}}}\n"
			}
			doc, _, err := schema.ParseStandaloneYAML([]byte(input))
			require.NoError(t, err)
			cfg, err := convert.DocumentToRuntime(doc)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(t.Context())
			queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
			run, err := otel.TracesReceiver(
				&global.ContextInfo{Metrics: imetrics.NoopReporter{}},
				cfg.Traces, false,
				&attributes.SelectorConfig{
					SelectionCfg:            cfg.Attributes.Select,
					SensitiveQueryParamsCfg: cfg.Attributes.SensitiveQueryParams,
				}, queue,
			)(ctx)
			require.NoError(t, err)
			done := make(chan struct{})
			go func() {
				defer close(done)
				run(ctx)
			}()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("trace exporter did not stop")
				}
			}()

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
			var td ptrace.Traces
			select {
			case td = <-exported:
			case <-time.After(5 * time.Second):
				t.Fatal("no OTLP traces exported")
			}
			require.Equal(t, 2, td.SpanCount())
			var clients, servers int
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
							require.Equal(t, !test.excludeQuery, ok)
							if ok {
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
