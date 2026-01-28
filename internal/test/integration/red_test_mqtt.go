// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

func runMQTTTestCase(t *testing.T, testCase TestCase) {
	t.Helper()

	var (
		url     = testCase.Route
		urlPath = testCase.Subpath
		comm    = testCase.Comm
	)

	// Make an HTTP request to trigger MQTT publish/subscribe
	req, err := http.NewRequest(http.MethodGet, url+"/"+urlPath, nil)
	require.NoError(t, err, "failed to create HTTP request")
	resp, err := testHTTPClient.Do(req)
	require.NoError(t, err, "failed to execute HTTP request")
	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code")

	// Ensure we see the expected spans in Jaeger
	test.Eventually(t, 2*testTimeout, func(t require.TestingT) {
		for _, span := range testCase.Spans {
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&limit=1000")
			require.NoError(t, err, "failed to query jaeger for %s", comm)
			if resp == nil {
				return
			}
			require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for jaeger query")
			var tq jaeger.TracesQuery
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response")
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(t, 1, len(traces), "span %s with tags %v not found in traces %v", span.Name, tags, tq.Data)
		}
	}, test.Interval(100*time.Millisecond))
}

func testREDMetricsPythonMQTT(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "mqtt"),
		attribute.Int("server.port", 1883),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "mqtt",
			Comm:    "python3.14",
			Spans: []TestCaseSpan{
				{
					Name: "publish test/topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "test/topic"),
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
			// Use /mqtt/connect for warmup to establish connection without triggering publish.
			// This ensures OBI is fully ready before the actual test triggers the publish operation.
			waitForMQTTTestComponents(t, testCase.Route, "/mqtt/connect")
			runMQTTTestCase(t, testCase)
		})
	}
}

func testREDMetricsPythonMQTTSubscribe(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "mqtt"),
		attribute.Int("server.port", 1883),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "mqtt/subscribe",
			Comm:    "python3.14",
			Spans: []TestCaseSpan{
				{
					Name: "process test/topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						attribute.String("messaging.destination.name", "test/topic"),
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
			// Use /mqtt/connect for warmup to establish connection without triggering subscribe.
			// This ensures OBI is fully ready before the actual test triggers the subscribe operation.
			waitForMQTTTestComponents(t, testCase.Route, "/mqtt/connect")
			runMQTTTestCase(t, testCase)
		})
	}
}

func waitForMQTTTestComponents(t *testing.T, url string, subpath string) {
	t.Helper()

	test.Eventually(t, time.Minute, func(t require.TestingT) {
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)
	}, test.Interval(time.Second))
}
