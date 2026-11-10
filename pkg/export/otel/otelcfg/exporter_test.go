// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const testTimeout = 5 * time.Second

// Tests that the Instantiate method of Exporter always returns handles to the same instance
// even if invoked concurrently
func TestSingleton(t *testing.T) {
	defer RestoreEnvAfterExecution()()

	concurrency := 50
	instancer := MetricsExporterInstancer{
		Cfg: &MetricsConfig{
			MetricsEndpoint: "http://localhost:4137",
		},
	}
	// run multiple exporters concurrently
	exporters := make(chan sdkmetric.Exporter, concurrency)
	errs := make(chan error, concurrency)
	for range concurrency {
		go func() {
			if exp, err := instancer.Instantiate(t.Context()); err != nil {
				errs <- err
			} else {
				exporters <- exp
			}
		}()
	}
	// all the Instantiate invocations should share the same instance
	get := func() sdkmetric.Exporter {
		select {
		case <-time.After(testTimeout):
			t.Fatal("timeout waiting for exporter")
		case exp := <-exporters:
			return exp.(*sharedMetricsExporter).Exporter
		case err := <-errs:
			t.Fatalf("unexpected error: %v", err)
		}
		return nil
	}
	ref := get()
	for i := 0; i < concurrency-1; i++ {
		if exp := get(); exp != ref {
			t.Fatalf("expected exporter to be the same as %p, got %p", ref, exp)
		}
	}
}

func TestHTTPJSONMetricsProtocolWarns(t *testing.T) {
	for _, tc := range []struct {
		name            string
		protocol        Protocol
		metricsProtocol Protocol
		wantWarn        bool
	}{
		{name: "http/json warns", protocol: ProtocolHTTPJSON, wantWarn: true},
		// Set from OTEL_EXPORTER_OTLP_METRICS_PROTOCOL.
		{name: "metrics-specific http/json warns", metricsProtocol: ProtocolHTTPJSON, wantWarn: true},
		{name: "http/protobuf does not warn", protocol: ProtocolHTTPProtobuf, wantWarn: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer RestoreEnvAfterExecution()()

			var logOutput bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logOutput, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })

			instancer := MetricsExporterInstancer{
				Cfg: &MetricsConfig{
					MetricsEndpoint: "http://localhost:4318",
					Protocol:        tc.protocol,
					MetricsProtocol: tc.metricsProtocol,
				},
			}
			_, err := instancer.Instantiate(t.Context())
			require.NoError(t, err)

			warned := bytes.Contains(logOutput.Bytes(), []byte("does not support JSON encoding"))
			assert.Equal(t, tc.wantWarn, warned)
		})
	}
}

type shutdownCountingExporter struct {
	sdkmetric.Exporter
	shutdowns int
}

func (e *shutdownCountingExporter) Shutdown(_ context.Context) error {
	e.shutdowns++
	return nil
}

func TestSharedExporterShutsDownAfterTheLastUser(t *testing.T) {
	underlying := &shutdownCountingExporter{Exporter: NewOTLPConsumerExporter(nil)}
	instancer := MetricsExporterInstancer{instance: underlying}

	first, err := instancer.Instantiate(t.Context())
	require.NoError(t, err)
	second, err := instancer.Instantiate(t.Context())
	require.NoError(t, err)

	require.NoError(t, first.Shutdown(t.Context()))
	require.NoError(t, first.Shutdown(t.Context()))
	assert.Zero(t, underlying.shutdowns, "the exporter is still used by the second handle")

	require.NoError(t, second.Shutdown(t.Context()))
	assert.Equal(t, 1, underlying.shutdowns)
}
