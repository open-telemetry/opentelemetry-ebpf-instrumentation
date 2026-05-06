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
func TestCloudResourceMetadata_AWS(t *testing.T) {
	network := setupDockerNetwork(t)
	setupAWSMockIMDS(t, network)
	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	setupGoOTelTestServer(t, network, nil)

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	// Configure OBI to use the mock IMDS by setting the EC2 metadata endpoint
	o := obi{
		Env: []string{
			`OTEL_EBPF_PROMETHEUS_PORT=8999`,
			"OTEL_EBPF_OPEN_PORT=8080",
			// Configure AWS SDK to use custom endpoint for EC2 metadata
			"AWS_EC2_METADATA_SERVICE_ENDPOINT=http://mock-imds:80",
		},
		Logs: createLogOutput(t, "cloud-meta-aws"),
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
		testAWSMetrics(t, pq, "rolldice", "otel")
	})
	t.Run("Prometheus metrics", func(t *testing.T) {
		testAWSMetrics(t, pq, "rolldice", "prometheus")
	})
	t.Run("OTEL traces", func(t *testing.T) {
		testAWSTraces(t)
	})
}

func testAWSMetrics(t *testing.T, pq promtest.Client, serviceName, exporter string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// attribute values taken from aws-metadata-mock.json
		query := `target_info{` +
			`service_name="` + serviceName + `",` +
			`exported="` + exporter + `",` +
			`cloud_account_id="0123456789",` +
			`cloud_availability_zone="us-east-1f",` +
			`cloud_platform="aws_ec2",` +
			`cloud_provider="aws",` +
			`cloud_region="us-east-1",` +
			`host_id="i-1234567890abcdef0",` +
			`host_image_id="ami-0b69ea66ff7391e80",` +
			`host_type="m4.xlarge"` +
			`}`
		results, err := pq.Query(query)
		require.NoError(ct, err, "failed to query metrics")
		assert.NotEmpty(ct, results, "target_info with cloud metadata should exist")
	}, testTimeout, 500*time.Millisecond)
}

func testAWSTraces(t *testing.T) {
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
			{Key: "cloud.account.id", Type: "string", Value: "^0123456789$"},
			{Key: "cloud.availability_zone", Type: "string", Value: "^us-east-1f$"},
			{Key: "cloud.platform", Type: "string", Value: "^aws_ec2$"},
			{Key: "cloud.provider", Type: "string", Value: "^aws$"},
			{Key: "cloud.region", Type: "string", Value: "^us-east-1$"},
			{Key: "host.id", Type: "string", Value: "^i-1234567890abcdef0$"},
			{Key: "host.image.id", Type: "string", Value: "^ami-0b69ea66ff7391e80$"},
			{Key: "host.type", Type: "string", Value: "^m4.xlarge$"},
		}, proc.Tags)
		require.Empty(t, sd)
	}
}
