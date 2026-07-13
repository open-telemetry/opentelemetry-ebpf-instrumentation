// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func TestUnixSocketTracesExporter(t *testing.T) {
	// On Linux "@"-prefixed names are abstract sockets (no filesystem entry,
	// cleaned up by the kernel). macOS doesn't support abstract sockets, so this
	// becomes a regular socket file in the working directory; remove any leftover
	// from an interrupted previous run before listening.
	const sockAddr = "@obi-test-traces"
	_ = os.Remove(sockAddr)

	lis, err := net.Listen("unix", sockAddr)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = lis.Close()
		_ = os.Remove(sockAddr)
	})

	gotPath := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotPath <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Close()

	cfg := otelcfg.TracesConfig{
		TracesEndpoint:   "unix://@obi-test-traces",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}
	exp, host, err := getTracesExporter(context.Background(), cfg, nil)
	require.NoError(t, err)
	require.NoError(t, exp.Start(context.Background(), host))
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

	traces := ptrace.NewTraces()
	traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty().SetName("test")
	require.NoError(t, exp.ConsumeTraces(context.Background(), traces))

	select {
	case path := <-gotPath:
		assert.Equal(t, "/v1/traces", path)
	case <-time.After(5 * time.Second):
		t.Fatal("traces request not received over unix socket")
	}
}
