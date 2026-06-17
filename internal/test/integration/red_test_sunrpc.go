// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// sunRPCTraceSearchAttrs returns Jaeger tag matchers for onc_rpc client spans.
// Keep aligned with tracesgen.TraceAttributesSelector SunRPC branch.
func sunRPCTraceSearchAttrs(prog string, proc, version int) []attribute.KeyValue {
	return []attribute.KeyValue{
		request.RPCSystem("onc_rpc"),
		semconv.OncRPCProgramName(prog),
		semconv.OncRPCProcedureNumber(proc),
		semconv.OncRPCVersion(version),
	}
}

func runSunRPCTestCase(t *testing.T, testCase TestCase) {
	t.Helper()

	var (
		url     = testCase.Route
		urlPath = testCase.Subpath
		comm    = testCase.Comm
	)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, url+"/"+urlPath, nil)
		require.NoError(ct, err)
		resp, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		for _, span := range testCase.Spans {
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&limit=1000")
			require.NoError(ct, err)
			if resp == nil {
				return
			}
			require.Equal(ct, http.StatusOK, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(ct, 1, len(traces), "span %s with tags %v not found in traces %v", span.Name, tags, tq.Data)
		}
	}, 2*testTimeout, time.Second)
}

func testREDMetricsGoSunRPC(t *testing.T) {
	commonAttrs := sunRPCTraceSearchAttrs("portmapper", 0, 2)

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "sunrpc",
			Comm:    "testserver",
			Spans: []TestCaseSpan{
				{
					Name: "portmapper/0",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "client"),
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, commonAttrs...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForHTTP200(t, testCase.Route+"/health")
			runSunRPCTestCase(t, testCase)
		})
	}
}

func testREDMetricsGoSunRPCPrometheus(t *testing.T) {
	const (
		url     = "http://localhost:8381"
		subpath = "sunrpc"
		svcNs   = "integration-test"
		svcName = "testserver"
	)

	waitForHTTP200(t, url+"/health")

	for range 4 {
		req, err := http.NewRequest(http.MethodGet, url+"/"+subpath, nil)
		require.NoError(t, err)
		resp, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	pq := promtest.Client{HostPort: prometheusHostPort}

	// SunRPC uses the same semconv rpc.*.call.duration metrics as gRPC; rpc.system.name distinguishes protocols.
	var clientResults []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		clientResults, err = pq.Query(`rpc_client_call_duration_seconds_count{` +
			`rpc_system_name="onc_rpc",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="` + svcName + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, clientResults)
		val := totalPromCount(ct, clientResults)
		assert.LessOrEqual(ct, 1, val)
	}, 2*testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`rpc_server_call_duration_seconds_count{` +
			`rpc_system_name="onc_rpc",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="` + svcName + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)
	}, 2*testTimeout, 100*time.Millisecond)
}

func waitForHTTP200(t *testing.T, url string) {
	t.Helper()
	require.Eventually(t, func() bool {
		resp, err := testHTTPClient.Get(url)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, testTimeout, 500*time.Millisecond)
}
