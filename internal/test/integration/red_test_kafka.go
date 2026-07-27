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

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func runKafkaTestCase(t *testing.T, testCase TestCase) {
	t.Helper()

	var (
		pq = promtest.Client{HostPort: prometheusHostPort}

		url     = testCase.Route
		urlPath = testCase.Subpath
		comm    = testCase.Comm

		results []promtest.Result
		err     error
	)

	ti.DoHTTPGet(t, url+"/"+urlPath, 200)

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))

	// Ensure we see the expected spans in Jaeger
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, span := range testCase.Spans {
			command := span.Name
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&limit=1000")
			require.NoError(ct, err, "failed to query jaeger for %s", comm)
			if resp == nil {
				return
			}
			require.Equal(ct, http.StatusOK, resp.StatusCode, "unexpected status code for %s: %d", command, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for %s", command)
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(ct, 1, len(traces), "span %s with tags %v not found in traces %v", command, tags, tq.Data)
		}
	}, 2*testTimeout, 100*time.Millisecond)

	// Ensure we don't find any HTTP traces, since we filter them out
	resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2F" + urlPath)
	require.NoError(t, err, "failed to query jaeger for HTTP traces")
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for HTTP traces: %d", resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for HTTP traces")
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + urlPath})
	require.Empty(t, traces, "expected no HTTP traces, got %d", len(traces))
}

func testREDMetricsPythonKafkaOnly(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", 9092),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "message",
			Comm:    "python3.14",
			Spans: []TestCaseSpan{
				{
					Name: "publish my-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "my-topic"),
						attribute.String("messaging.client.id", "kafka-python-producer-1"),
						attribute.String("messaging.destination.partition.id", "0"),
					},
				},
				{
					Name: "process my-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						attribute.String("messaging.destination.name", "my-topic"),
						attribute.String("messaging.destination.partition.id", "0"),
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
			waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			runKafkaTestCase(t, testCase)
		})
	}
}

func testJavaKafka(t *testing.T, port int, comm string) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", port),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "message",
			Comm:    comm,
			Spans: []TestCaseSpan{
				{
					Name: "publish my-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "my-topic"),
						attribute.String("messaging.client.id", "producer-1"),
						attribute.String("messaging.destination.partition.id", "0"),
					},
				},
				{
					// In here we can't recognize the topic name (so we use *) since the metadata response is cut to
					// the first 4 bytes in java, to get this to work we need to use eBPF large buffer feature for
					// kafka which is tested in testJavaKafkaLargeBuffer
					Name: "process *",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						// Sometimes we find my-topic (with TLS), sometimes we cannot we get *
						// attribute.String("messaging.destination.name", "*"),
						attribute.String("messaging.client.id", "consumer-1-1"),
						attribute.String("messaging.destination.partition.id", "0"),
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
			waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			runKafkaTestCase(t, testCase)
		})
	}
}

func testJavaKafkaLargeBuffer(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", 9092),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "message",
			Comm:    "javakafka-lb",
			Spans: []TestCaseSpan{
				{
					Name: "publish theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree"),
						attribute.String("messaging.client.id", "producer-1"),
						attribute.String("messaging.destination.partition.id", "0"),
					},
				},
				{
					Name: "process theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						attribute.String("messaging.destination.name", "theotelebpfagentisperfectlyimpatientitskipsthecodethesdkandfindsthekernelssecretkeyitwatcheshttpandgrpctogiveyoumetricsforfreeapowerfulkernellevelspree"),
						attribute.String("messaging.client.id", "consumer-1-1"),
						attribute.String("messaging.destination.partition.id", "0"),
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
			waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			runKafkaTestCase(t, testCase)
		})
	}
}

// testNodeRdkafka exercises a librdkafka (confluent-kafka-javascript) client,
// which negotiates Fetch/Produce v13+ (topic-by-UUID). The client uses a single
// topic with many partitions so the broker's metadata response is large enough
// to arrive across multiple recv() chunks. Asserts the real topic name resolves
// (not "*"): fails without the eBPF multi-chunk capture because the response body
// was dropped, so the topic UUID->name mapping was never learned.
func testNodeRdkafka(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", 9092),
	}

	testCases := []TestCase{
		{
			Route:   "http://localhost:8381",
			Subpath: "health",
			Comm:    "node",
			Spans: []TestCaseSpan{
				{
					Name: "publish obi-node-rdkafka-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "producer"),
						attribute.String("messaging.operation.type", "publish"),
						attribute.String("messaging.destination.name", "obi-node-rdkafka-topic"),
					},
				},
				{
					Name: "process obi-node-rdkafka-topic",
					Attributes: []attribute.KeyValue{
						attribute.String("span.kind", "consumer"),
						attribute.String("messaging.operation.type", "process"),
						attribute.String("messaging.destination.name", "obi-node-rdkafka-topic"),
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
			waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			runKafkaTestCase(t, testCase)
		})
	}
}

// testJavaKafkaMultiTopic exercises the Apache Java client (Fetch/Produce v13+,
// topic-by-UUID) subscribing to several topics, so the broker's Metadata
// response is multi-topic. OBI must resolve every topic to its real name.
// A parser that only handles the first topic leaves the others as "*",
// so asserting all of them resolves guards the multi-topic metadata parsing
// regardless of the broker's topic ordering.
//
// Note the asymmetry: the Apache Java producer sends a separate single-topic
// Produce per topic, so the `publish <topic>` assertions pass even without the
// multi-topic changes. The real coverage is the `process <topic>` assertions:
// the Java consumer issues one multi-topic Fetch (all subscribed topics by UUID),
// so all three `process` spans appearing is what proves the metadata
// multi-topic parse + fetch alignment + per-topic span emission are working together.
func testJavaKafkaMultiTopic(t *testing.T) {
	commonAttrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.Int("server.port", 9092),
	}

	topics := []string{
		"obi-java-multitopic-1",
		"obi-java-multitopic-2",
		"obi-java-multitopic-3",
	}

	var spans []TestCaseSpan
	for _, topic := range topics {
		spans = append(spans,
			TestCaseSpan{
				Name: "publish " + topic,
				Attributes: []attribute.KeyValue{
					attribute.String("span.kind", "producer"),
					attribute.String("messaging.operation.type", "publish"),
					attribute.String("messaging.destination.name", topic),
				},
			},
			TestCaseSpan{
				Name: "process " + topic,
				Attributes: []attribute.KeyValue{
					attribute.String("span.kind", "consumer"),
					attribute.String("messaging.operation.type", "process"),
					attribute.String("messaging.destination.name", topic),
				},
			},
		)
	}

	testCase := TestCase{
		Route:   "http://localhost:8381",
		Subpath: "message",
		Comm:    "javakafka-mt",
		Spans:   spans,
	}

	for i := range testCase.Spans {
		testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, commonAttrs...)
	}

	t.Run(testCase.Route, func(t *testing.T) {
		waitForKafkaTestComponents(t, testCase.Route, "/"+testCase.Subpath)
		runKafkaTestCase(t, testCase)
	})
}

func waitForKafkaTestComponents(t *testing.T, url string, subpath string) {
	t.Helper()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)
	}, time.Minute, time.Second)
}
