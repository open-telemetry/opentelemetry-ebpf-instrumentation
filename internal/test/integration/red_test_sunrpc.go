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
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

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
	commonAttrs := []attribute.KeyValue{
		semconv.RPCSystemOncRPC,
		semconv.OncRPCProgramName("portmapper"),
		semconv.OncRPCProcedureNumber(0),
		semconv.OncRPCVersion(2),
	}

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
