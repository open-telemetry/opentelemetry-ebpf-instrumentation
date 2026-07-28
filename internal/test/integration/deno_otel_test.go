// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// OBI is able to instrument Deno's HTTP signals at the same level as Node.js.
// However, OBI cannot decrypt Deno's HTTPS because Deno uses statically-linked,
// stripped rustls.
// Tests in this file verify that users can still run Deno's native OTEL instrumentation
// (--unstable-otel + OTEL_DENO=true) and OBI will detect it and suppress any
// duplicate telemetry.
// Tests verify both: Deno's own spans reach the backend, and OBI flags the service as
// OTel-instrumented for traces AND metrics (no duplication).

func denoOTelWarmup(t *testing.T) {
	// Generate traffic so Deno produces and exports spans (and metrics on its
	// periodic interval); OBI observes the /v1/traces and /v1/metrics export
	// calls and flags the service.
	for range 10 {
		ti.DoHTTPGet(t, "http://localhost:3031/nested-plain", 200)
		time.Sleep(20 * time.Millisecond)
	}
}

func processTag(p jaeger.Process, key string) (string, bool) {
	for _, tg := range p.Tags {
		if tg.Key == key {
			if s, ok := tg.Value.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

// testDenoNativeOTelSpans asserts Deno's own OTel spans reach Jaeger, identified
// by the Deno SDK resource attribute telemetry.sdk.name=deno-opentelemetry.
func testDenoNativeOTelSpans(t *testing.T) {
	waitForTestComponents(t, "http://localhost:3031")
	denoOTelWarmup(t)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&limit=100")
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data, "expected testserver traces in Jaeger")

		sawDenoSDK := false
		for _, tr := range tq.Data {
			for _, p := range tr.Processes {
				if p.ServiceName != "testserver" {
					continue
				}
				if lang, ok := processTag(p, "telemetry.sdk.name"); ok && lang == "deno-opentelemetry" {
					sawDenoSDK = true
				}
			}
		}
		require.True(ct, sawDenoSDK,
			"expected at least one testserver span emitted by Deno's own OTel SDK (telemetry.sdk.name=deno-opentelemetry)")
	}, testTimeout, 500*time.Millisecond)
}

// testDenoNativeOTelNoDuplicate asserts OBI detected the Deno service as already
// exporting OTLP and suppressed its own telemetry for BOTH traces and metrics -
// i.e. no duplication. The signal is OBI's internal obi_avoided_services gauge.
func testDenoNativeOTelNoDuplicate(t *testing.T) {
	denoOTelWarmup(t)

	assertAvoidedService(t, "testserver", "traces")
	assertAvoidedService(t, "testserver", "metrics")
}

func assertAvoidedService(t *testing.T, serviceName, telemetryType string) {
	t.Helper()
	const internalMetricsURL = "http://localhost:8999/internal/metrics"

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		parser := expfmt.NewTextParser(model.UTF8Validation)
		resp, err := http.Get(internalMetricsURL)
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		metrics, err := parser.TextToMetricFamilies(resp.Body)
		require.NoError(ct, err)

		mf, ok := metrics["obi_avoided_services"]
		require.True(ct, ok, "obi_avoided_services metric should be present")

		found := false
		for _, m := range mf.Metric {
			labels := make(map[string]string, len(m.Label))
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["service_name"] == serviceName && labels["telemetry_type"] == telemetryType {
				if m.Gauge != nil && m.Gauge.GetValue() > 0 {
					found = true
				}
			}
		}
		require.True(ct, found,
			"expected obi_avoided_services{service_name=%q,telemetry_type=%q} > 0 (OBI should suppress its own %s for an OTel-instrumented Deno service)",
			serviceName, telemetryType, telemetryType)
	}, testTimeout, 1*time.Second)
}
