// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

type recordedRequest struct {
	contentType string
	path        string
	body        []byte
}

func collectorRecordingRequest(t *testing.T, got *atomic.Pointer[recordedRequest]) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		got.CompareAndSwap(nil, &recordedRequest{contentType: r.Header.Get("Content-Type"), path: r.URL.Path, body: body})
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTracesExportHTTPPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		wantPath string
	}{
		{name: "endpoint without path", wantPath: "/v1/traces"},
		{name: "explicit path", path: "/custom/traces", wantPath: "/custom/traces"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got atomic.Pointer[recordedRequest]
			coll := collectorRecordingRequest(t, &got)
			endpoint := coll.URL + tc.path
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", endpoint)

			cfg := baseTracesConfig("")
			cfg.TracesEndpoint = endpoint
			exportOneSpan(t, cfg)

			require.Eventually(t, func() bool { return got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
				"the collector never received an export")
			assert.Equal(t, tc.wantPath, got.Load().path)
		})
	}
}

func TestTracesExportEncodingHTTP(t *testing.T) {
	for _, tc := range []struct {
		name            string
		protocol        otelcfg.Protocol
		wantContentType string
		unmarshal       func(ptraceotlp.ExportRequest, []byte) error
	}{
		{
			name:            "unset sends protobuf",
			protocol:        "",
			wantContentType: "application/x-protobuf",
			unmarshal:       ptraceotlp.ExportRequest.UnmarshalProto,
		},
		{
			name:            "http/protobuf sends protobuf",
			protocol:        otelcfg.ProtocolHTTPProtobuf,
			wantContentType: "application/x-protobuf",
			unmarshal:       ptraceotlp.ExportRequest.UnmarshalProto,
		},
		{
			name:            "http/json sends json",
			protocol:        otelcfg.ProtocolHTTPJSON,
			wantContentType: "application/json",
			unmarshal:       ptraceotlp.ExportRequest.UnmarshalJSON,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got atomic.Pointer[recordedRequest]
			coll := collectorRecordingRequest(t, &got)

			cfg := baseTracesConfig(coll.URL)
			cfg.Protocol = tc.protocol
			exportOneSpan(t, cfg)

			require.Eventually(t, func() bool { return got.Load() != nil }, 5*time.Second, 20*time.Millisecond,
				"the collector never received an export")
			req := got.Load()
			assert.Equal(t, tc.wantContentType, req.contentType)

			decoded := ptraceotlp.NewExportRequest()
			require.NoError(t, tc.unmarshal(decoded, req.body))
			assert.Equal(t, 1, decoded.Traces().SpanCount())
		})
	}
}
