// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	comm          = "python3.14"
	testIndex     = "test_index"
	testServerURL = "http://localhost:8381"
)

func testPythonElasticsearch(t *testing.T, dbSystemName string) {
	var url string
	switch dbSystemName {
	case "elasticsearch":
		url = "http://elasticsearchserver:9200"
	case "opensearch":
		url = "http://opensearchserver:9200"
	}
	queryParam := "?host_url=" + url
	waitForTestComponentsNoMetrics(t, testServerURL+"/health"+queryParam)
	testElasticsearchSearch(t, dbSystemName, queryParam)
	// populate the server is optional, the elasticsearch request will fail
	// but we will have the span
	testElasticsearchMsearch(t, dbSystemName, queryParam)
	testElasticsearchBulk(t, dbSystemName, queryParam)
	testElasticsearchDoc(t, dbSystemName, queryParam)
}

func testElasticsearchSearch(t *testing.T, dbSystemName, queryParam string) {
	queryText := "{\"query\": {\"match\": {\"name\": \"OBI\"}}}"
	urlPath := "/search"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "search", queryText, testIndex)
}

func assertElasticsearchOperation(t *testing.T, dbSystemName, op, queryText, index string) {
	params := neturl.Values{}
	params.Add("service", comm)
	var operationName string
	if index != "" {
		operationName = op + " " + index
	} else {
		operationName = op
	}
	params.Add("operationName", operationName)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	require.Eventually(t, func() bool {
		resp, err := http.Get(fullJaegerURL)
		if err != nil {
			return false
		}
		if resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}

		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: op})
		if len(traces) < 1 {
			return false
		}
		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		if !strings.Contains(span.OperationName, operationName) {
			return false
		}

		tag, found := jaeger.FindIn(span.Tags, "db.query.text")
		if !found {
			return false
		}
		if tag.Value.(string) != queryText {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.collection.name")
		if !found {
			return false
		}
		if tag.Value != index {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.namespace")
		if !found {
			return false
		}
		if tag.Value != "" {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "db.system.name")
		if !found {
			return false
		}
		if tag.Value != dbSystemName {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "elasticsearch.node.name")
		if !found {
			return false
		}
		if tag.Value != "" {
			return false
		}

		return true
	}, testTimeout, 100*time.Millisecond, "Elasticsearch %s operation not found", op)
	}, test.Interval(100*time.Millisecond))
}

func testElasticsearchMsearch(t *testing.T, dbSystemName, queryParam string) {
	queryText := "[{}, {\"query\": {\"match\": {\"message\": \"this is a test\"}}}, {\"index\": \"my-index-000002\"}, {\"query\": {\"match_all\": {}}}]"
	urlPath := "/msearch"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "msearch", queryText, "")
}

func testElasticsearchBulk(t *testing.T, dbSystemName, queryParam string) {
	queryText := "[{\"index\": {\"_index\": \"test\", \"_id\": \"1\"}}, {\"field1\": \"value1\"}, {\"delete\": {\"_index\": \"test\", \"_id\": \"2\"}}, {\"create\": {\"_index\": \"test\", \"_id\": \"3\"}}, {\"field1\": \"value3\"}, {\"update\": {\"_id\": \"1\", \"_index\": \"test\"}}, {\"doc\": {\"field2\": \"value2\"}}]"
	urlPath := "/bulk"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "bulk", queryText, "")
}

func testElasticsearchDoc(t *testing.T, dbSystemName, queryParam string) {
	queryText := ""
	urlPath := "/doc"
	ti.DoHTTPGet(t, testServerURL+urlPath+queryParam, 200)
	assertElasticsearchOperation(t, dbSystemName, "doc", queryText, testIndex)
}
