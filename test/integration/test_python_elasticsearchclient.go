// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
	"go.opentelemetry.io/obi/test/integration/components/jaeger"
)

func testPythonElasticsearch(t *testing.T) {
	url := "http://localhost:8381"
	comm := "python3.12"
	index := "test_index"

	waitForTestComponentsRoute(t, url, "/health")
	// populate elasticsearch with a custom value
	populate(t, url)
	testElasticsearchSearch(t, comm, url, index)
}

func populate(t *testing.T, url string) {
	urlPath := "/doc"
	ti.DoHTTPGet(t, url+urlPath, 200)
}

func testElasticsearchSearch(t *testing.T, comm, url, index string) {
	queryText := "{\"query\":{\"match\":{\"name\":\"OBI\"}}}"
	urlPath := "/search"
	ti.DoHTTPGet(t, url+urlPath, 200)

	assertElasticsearchOperation(t, comm, "search", queryText, index)
}

func assertElasticsearchOperation(t *testing.T, comm, op, queryText, index string) {
	params := neturl.Values{}
	params.Add("service", comm)
	operatioName := op + " " + index
	params.Add("operationName", operatioName)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(fullJaegerURL)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: op})
		require.GreaterOrEqual(t, len(traces), 1)
		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		assert.Equal(t, operatioName, span.OperationName)

		tag, found := jaeger.FindIn(span.Tags, "db.query.text")
		assert.True(t, found)
		assert.JSONEq(t, queryText, tag.Value.(string))

		tag, found = jaeger.FindIn(span.Tags, "db.collection.name")
		assert.True(t, found)
		assert.Equal(t, index, tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "db.namespace")
		assert.True(t, found)
		assert.Empty(t, tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "db.system.name")
		assert.True(t, found)
		assert.Equal(t, "elasticsearch", tag.Value)

		tag, found = jaeger.FindIn(span.Tags, "elasticsearch.node.name")
		assert.True(t, found)
		assert.Empty(t, tag.Value)
	}, test.Interval(100*time.Millisecond))
}
