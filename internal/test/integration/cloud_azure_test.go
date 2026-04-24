// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// This file contains tests related with the integration with Amazon Web Services
func TestCloudResourceMetadata_Azure(t *testing.T) {
	network := setupIMDSSubnet(t)
	setupMockAzureIMDS(t, network)
	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	setupGoOTelTestServer(t, network, nil)

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	// Configure OBI to use the mock IMDS by setting the Azure metadata endpoint
	o := obi{
		Env: []string{
			`OTEL_EBPF_PROMETHEUS_PORT=8999`,
			"OTEL_EBPF_OPEN_PORT=8080",
		},
		Logs: createLogOutput(t, "cloud-meta-azure"),
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, "obi-config.yml")

	// Wait for test components to be ready
	waitForTestComponents(t, "http://localhost:8080")

	// Make some requests to generate metrics
	for range 4 {
		ti.DoHTTPGet(t, "http://localhost:8080/rolldice", 200)
	}

	// Query Prometheus for target_info with cluster_name attribute
	pq := promtest.Client{HostPort: prometheusHostPort}

	t.Run("OTEL metrics", func(t *testing.T) {
		testAzureMetrics(t, pq, "rolldice", "otel")
	})
	t.Run("Prometheus metrics", func(t *testing.T) {
		testAzureMetrics(t, pq, "rolldice", "prometheus")
	})
	t.Run("OTEL traces", func(t *testing.T) {
		testAzureTraces(t)
	})
}

func testAzureMetrics(t *testing.T, pq promtest.Client, serviceName, exporter string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// attribute values taken from aws-metadata-mock.json
		query := `target_info{` +
			`service_name="` + serviceName + `",` +
			`exported="` + exporter + `",` +
			`cloud_platform="azure.vm",` +
			`cloud_provider="azure",` +
			`cloud_region="westus",` +
			`cloud_resource_id="/long/tail/of/stuff",` +
			`host_id="02aab8a4-74ef-476e-8182-f6d2ba4166a6",` +
			`host_type="Standard_A3"` +
			`}`
		results, err := pq.Query(query)
		require.NoError(ct, err, "failed to query metrics")
		assert.NotEmpty(ct, results, "target_info with cloud metadata should exist")
	}, testTimeout, 500*time.Millisecond)
}

func testAzureTraces(t *testing.T) {
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2Frolldice")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
		require.Len(ct, trace.Spans, 3) // parent - in queue - processing
	}, testTimeout, 100*time.Millisecond)

	for _, proc := range trace.Processes {
		sd := jaeger.DiffAsRegexp([]jaeger.Tag{
			{Key: "cloud.platform", Type: "string", Value: "^azure.vm$"},
			{Key: "cloud.provider", Type: "string", Value: "^azure$"},
			{Key: "cloud.region", Type: "string", Value: "^westus$"},
			{Key: "cloud.resource_id", Type: "string", Value: "^/long/tail/of/stuff$"},
			{Key: "host.id", Type: "string", Value: "^02aab8a4-74ef-476e-8182-f6d2ba4166a6$"},
			{Key: "host.type", Type: "string", Value: "^Standard_A3$"},
		}, proc.Tags)
		require.Empty(t, sd)
	}
}
