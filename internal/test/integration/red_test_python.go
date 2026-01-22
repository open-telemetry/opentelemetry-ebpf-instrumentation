// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testREDMetricsForPythonHTTPLibrary(t *testing.T, url, comm, namespace string) {
	urlPath := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+urlPath, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `",` +
			`url_path="` + urlPath + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})
}

func testREDMetricsTimeoutForPythonHTTPLibrary(t *testing.T, url, comm, namespace string) {
	urlPath := "/black_hole"

	doHTTPGetWithTimeout(t, url+urlPath, 3*time.Second)

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="408",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `",` +
			`url_path="` + urlPath + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})
}

func testREDMetricsDNSForPython(t *testing.T, url, comm, namespace string) {
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+"/ok_dns", 200)
		ti.DoHTTPGet(t, url+"/bad_dns", 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`dns_lookup_duration_seconds_count{` +
			`dns_question_name="opentelemetry.io.",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)

		results, err = pq.Query(`dns_lookup_duration_seconds_count{` +
			`dns_question_name="www.opentelemetry.invalid.",` +
			`error_type="NXDomain",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val = totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})
}

func testREDMetricsPythonHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForPythonHTTPLibrary(t, testCaseURL, "python3.14", "integration-test")
		})
	}
}

func testREDMetricsTimeoutPythonHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsTimeoutForPythonHTTPLibrary(t, testCaseURL, "python3.14", "integration-test")
		})
	}
}

func testREDMetricsDNSPython(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsDNSForPython(t, testCaseURL, "python3.14", "integration-test")
		})
	}
}

func testREDMetricsPythonHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForPythonHTTPLibrary(t, testCaseURL, "python3.14", "integration-test")
		})
	}
}

func checkReportedPythonEvents(t *testing.T, comm, namespace string, numEvents int) {
	urlPath := "/greeting"

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `",` +
			`url_path="` + urlPath + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, val, numEvents)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})
}
