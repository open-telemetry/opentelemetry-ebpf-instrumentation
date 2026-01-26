// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Ruby test are up and communicating properly
func waitForRubyTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/users")
}

func testREDMetricsForRubyHTTPLibrary(t *testing.T, url string, comm string) {
	path := "/users"

	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	// add couple of record to users, we will get records id of 1,2,3,4
	jsonBody := []byte(`{"name": "Jane Doe", "email": "jane@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	jsonBody = []byte(`{"name": "John Doe", "email": "john@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	jsonBody = []byte(`{"name": "Mary Doe", "email": "mary@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	jsonBody = []byte(`{"name": "Mark Doe", "email": "mark@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	// Eventually, Prometheus would make this query visible
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="POST",` +
			`http_response_status_code="201",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`url_path="` + path + `"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 1
	}, testTimeout, 500*time.Millisecond, "failed to find POST http metrics")

	// check that the resource attributes we passed made it for the service
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`target_info{` +
			`data_center="ca",` +
			`deployment_zone="to"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 1
	}, testTimeout, 500*time.Millisecond, "failed to find target_info metric")

	// Call 4 times the instrumented service, forcing it to:
	// - process multiple calls in a row with, one more than we might need
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+path+"/1", 200)
	}

	// Eventually, Prometheus would make this query visible
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`url_path="` + path + `/1"}`)
		if err != nil {
			return false
		}
		if !enoughPromResultsCheck(results) {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 3
	}, testTimeout, 500*time.Millisecond, "failed to find GET http metrics")
}

func testREDMetricsRailsHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:3041",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForRubyTestComponents(t, testCaseURL)
			testREDMetricsForRubyHTTPLibrary(t, testCaseURL, "my-ruby-app")
		})
	}
}

func testREDMetricsRailsHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:3044",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForRubyTestComponents(t, testCaseURL)
			testREDMetricsForRubyHTTPLibrary(t, testCaseURL, "my-ruby-app")
		})
	}
}

// Assumes we've run the metrics tests
func testHTTPTracesNestedNginx(t *testing.T) {
	for i := 1; i <= 4; i++ {
		go ti.DoHTTPGet(t, "https://localhost:8443/users/"+strconv.Itoa(i), 200)
	}

	for i := 1; i <= 4; i++ {
		slug := strconv.Itoa(i)
		var trace jaeger.Trace
		require.Eventually(t, func() bool {
			resp, err := http.Get(jaegerQueryURL + "?service=nginx&tags=%7B%22url.path%22%3A%22%2Fusers%2F" + slug + "%22%7D")
			if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
				return false
			}
			var tq jaeger.TracesQuery
			if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
				return false
			}
			traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/users/" + slug})
			if len(traces) < 1 {
				return false
			}
			trace = traces[0]

			// Check the information of the server span
			res := trace.FindByOperationName("GET /users/"+slug, "server")
			if len(res) < 1 {
				return false
			}
			server := res[0]
			if server.TraceID == "" || server.SpanID == "" {
				return false
			}

			// check client call
			res = trace.FindByOperationName("GET /users/"+slug, "client")
			if len(res) < 1 {
				return false
			}
			client := res[0]
			return client.TraceID != "" && server.TraceID == client.TraceID && client.SpanID != ""
		}, testTimeout, 500*time.Millisecond, "failed to verify nginx traces")
	}
}

// Assumes we've run the metrics tests
func testHTTPTracesNestedNginxSQL(t *testing.T) {
	for i := 1; i <= 4; i++ {
		go ti.DoHTTPGet(t, "https://localhost:8443/users/"+strconv.Itoa(i), 200)
	}

	for i := 1; i <= 4; i++ {
		slug := strconv.Itoa(i)
		var trace jaeger.Trace
		require.Eventually(t, func() bool {
			resp, err := http.Get(jaegerQueryURL + "?service=nginx&tags=%7B%22url.path%22%3A%22%2Fusers%2F" + slug + "%22%7D")
			if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
				return false
			}
			var tq jaeger.TracesQuery
			if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
				return false
			}
			traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/users/" + slug})
			if len(traces) < 1 {
				return false
			}
			trace = traces[0]

			// Check the information of the server span
			res := trace.FindByOperationName("GET /users/"+slug, "server")
			if len(res) < 1 {
				return false
			}
			server := res[0]
			if server.TraceID == "" || server.SpanID == "" {
				return false
			}

			// check client call
			res = trace.FindByOperationName("GET /users/"+slug, "client")
			if len(res) < 1 {
				return false
			}
			client := res[0]
			if client.TraceID == "" || server.TraceID != client.TraceID || client.SpanID == "" {
				return false
			}

			// check SQL client call
			res = trace.FindByOperationName("SELECT users", "client")
			if len(res) < 1 {
				return false
			}
			client = res[0]
			return client.TraceID != "" && server.TraceID == client.TraceID && client.SpanID != ""
		}, testTimeout, 500*time.Millisecond, "failed to verify nginx SQL traces")
	}
}
