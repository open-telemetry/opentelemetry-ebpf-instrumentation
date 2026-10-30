// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const minioValidationService = "minio-validation"

// TestMinIOServerSpans checks the request counts and endpoints reported in #3725
// against a real MinIO server with Go instrumentation enabled.
func TestMinIOServerSpans(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-minio-server.yml", path.Join(pathOutput, "test-suite-minio-server.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	require.Eventually(t, func() bool {
		resp, err := client.Get("http://localhost:19000/minio/health/cluster")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK && hasSpansInJaeger(minioValidationService)
	}, 2*time.Minute, time.Second)

	logs, err := compose.LogsTail(200, "obi")
	require.NoError(t, err)
	require.Regexp(t, `instrumenting process[^\n]*type=go`, logs, "MinIO must use Go instrumentation")
	minioValidationRequest(t, client, http.MethodPut, "/kb-files")

	for _, keepAlive := range []bool{false, true} {
		t.Run(fmt.Sprintf("keepalive=%t", keepAlive), func(t *testing.T) {
			testMinIORequestCounts(t, keepAlive)
		})
	}
}

func testMinIORequestCounts(t *testing.T, keepAlive bool) {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: !keepAlive},
		Timeout:   5 * time.Second,
	}
	defer client.CloseIdleConnections()

	beforeMetrics := minioServerRequestCounts(t)
	beforeSpans := serverSpansByPath(t, minioValidationService)
	requests := map[string]int{
		"/kb-files/":          7,
		"/minio/health/ready": 9,
		"/minio/health/live":  3,
	}
	for requestPath, count := range requests {
		for range count {
			minioValidationRequest(t, client, http.MethodGet, requestPath)
		}
	}
	client.CloseIdleConnections()

	checkCounts := func(ct *assert.CollectT) {
		metrics := minioServerRequestCounts(ct)
		spans := serverSpansByPath(ct, minioValidationService)
		for requestPath, count := range requests {
			assert.InDelta(ct, float64(count), metrics[requestPath]-beforeMetrics[requestPath], 0,
				"%s: Prometheus counter delta must equal requests sent", requestPath)
			assert.Len(ct, spans[requestPath], len(beforeSpans[requestPath])+count,
				"%s: one server span per request", requestPath)
			for _, span := range spans[requestPath] {
				assert.Empty(ct, span.Diff(
					jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(9000)},
					jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(http.StatusOK)},
				), requestPath)
				peer, ok := jaeger.FindIn(span.Tags, "network.peer.address")
				assert.True(ct, ok, requestPath)
				assert.NotEmpty(ct, peer.Value, requestPath)
				port, ok := jaeger.FindIn(span.Tags, "network.peer.port")
				assert.True(ct, ok, requestPath)
				assert.Positive(ct, port.Value, requestPath)
			}
		}
	}
	require.EventuallyWithT(t, checkCounts, 30*time.Second, time.Second)
	// Allow delayed generic events to expose duplicate requests.
	time.Sleep(2 * time.Second)
	require.EventuallyWithT(t, checkCounts, time.Second, 100*time.Millisecond)
}

func minioValidationRequest(t *testing.T, client *http.Client, method, requestPath string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, "http://localhost:19000"+requestPath, http.NoBody)
	require.NoError(t, err)
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(nil))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	err = v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{
		AccessKeyID: "minioadmin", SecretAccessKey: "minioadmin123",
	}, req, payloadHash, "s3", "us-east-1", time.Now())
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s %s: %s", method, requestPath, body)
}

func minioServerRequestCounts(t require.TestingT) map[string]float64 {
	metrics, err := promtest.Scrape("http://localhost:19400/metrics")
	require.NoError(t, err)
	counts := map[string]float64{}
	for _, metric := range metrics {
		if metric.Name == "http_server_request_duration_seconds_count" &&
			metric.Labels["service_name"] == minioValidationService &&
			metric.Labels["http_request_method"] == http.MethodGet {
			counts[metric.Labels["http_route"]] += metric.Value
		}
	}
	return counts
}
