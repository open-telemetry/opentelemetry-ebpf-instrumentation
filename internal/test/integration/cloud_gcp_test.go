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

// This file contains tests related with the integration with Google Cloud Platform
func TestCloudResourceMetadata_GCP(t *testing.T) {
	network := setupDockerNetwork(t)
	setupMockGCPIMDS(t, network)

	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	setupGoOTelTestServer(t, network, nil)

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	o := obi{
		Env: []string{
			`OTEL_EBPF_PROMETHEUS_PORT=8999`,
			"OTEL_EBPF_OPEN_PORT=8080",
			"GCE_METADATA_HOST=mock-imds",
		},
		Logs: createLogOutput(t, "cloud-meta-gcp"),
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

	// Query Prometheus for target_info with cloud metadata attributes
	pq := promtest.Client{HostPort: prometheusHostPort}

	t.Run("OTEL metrics", func(t *testing.T) {
		testGCPMetrics(t, pq, "rolldice", "otel")
	})
	t.Run("Prometheus metrics", func(t *testing.T) {
		testGCPMetrics(t, pq, "rolldice", "prometheus")
	})
	t.Run("OTEL traces", func(t *testing.T) {
		testGCPTraces(t)
	})
}

func testGCPMetrics(t *testing.T, pq promtest.Client, serviceName, exporter string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// attribute values taken from gcp-imds/nginx.conf mock
		query := `target_info{` +
			`service_name="` + serviceName + `",` +
			`exported="` + exporter + `",` +
			`cloud_account_id="my-test-project",` +
			`cloud_availability_zone="us-central1-a",` +
			`cloud_platform="gcp_compute_engine",` +
			`cloud_provider="gcp",` +
			`cloud_region="us-central1",` +
			`gcp_gce_instance_hostname="test-instance.c.my-test-project.internal",` +
			`gcp_gce_instance_name="test-instance",` +
			`host_id="1234567890123456789",` +
			`host_type="n1-standard-1"` +
			`}`
		results, err := pq.Query(query)
		require.NoError(ct, err, "failed to query metrics")
		assert.NotEmpty(ct, results, "target_info with cloud metadata should exist")
	}, testTimeout, 500*time.Millisecond)
}

func testGCPTraces(t *testing.T) {
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
			{Key: "cloud.account.id", Type: "string", Value: "^my-test-project$"},
			{Key: "cloud.availability_zone", Type: "string", Value: "^us-central1-a$"},
			{Key: "cloud.platform", Type: "string", Value: "^gcp_compute_engine$"},
			{Key: "cloud.provider", Type: "string", Value: "^gcp$"},
			{Key: "cloud.region", Type: "string", Value: "^us-central1$"},
			{Key: "gcp.gce.instance.hostname", Type: "string", Value: "^test-instance.c.my-test-project.internal"},
			{Key: "gcp.gce.instance.name", Type: "string", Value: "^test-instance"},
			{Key: "host.id", Type: "string", Value: "^1234567890123456789$"},
			{Key: "host.type", Type: "string", Value: "^n1-standard-1$"},
		}, proc.Tags)
		require.Empty(t, sd)
	}
}
