// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestTraceAttributesSelector_ElasticsearchResponseStatusCode(t *testing.T) {
	esSpan := func(status int) *request.Span {
		return &request.Span{
			Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeElasticsearch,
			Method: "POST", Path: "/my-index/_search", Host: "es", HostPort: 9200,
			Status: status,
			Elasticsearch: &request.Elasticsearch{
				DBSystemName:    "elasticsearch",
				DBOperationName: "search",
			},
		}
	}

	lookup := func(attrs []attribute.KeyValue, key string) (string, bool) {
		for _, kv := range attrs {
			if string(kv.Key) == key {
				return kv.Value.Emit(), true
			}
		}
		return "", false
	}

	for _, status := range []int{200, 404, 429, 503} {
		t.Run("reports the cluster status", func(t *testing.T) {
			attrs := TraceAttributesSelector(esSpan(status), map[attr.Name]struct{}{})
			v, ok := lookup(attrs, "db.response.status_code")
			require.True(t, ok, "status %d", status)
			assert.Equal(t, strconv.Itoa(status), v)
		})
	}

	t.Run("omitted when no response was received", func(t *testing.T) {
		attrs := TraceAttributesSelector(esSpan(0), map[attr.Name]struct{}{})
		_, ok := lookup(attrs, "db.response.status_code")
		assert.False(t, ok, "conditionally required only if a response was received")
	})
}

func TestTraceAttributesSelector_ElasticsearchNamespace(t *testing.T) {
	esSpan := func(index, cluster string) *request.Span {
		return &request.Span{
			Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeElasticsearch,
			Method: "POST", Path: "/_search", Host: "es", HostPort: 9200,
			Status:      200,
			DBNamespace: cluster,
			Elasticsearch: &request.Elasticsearch{
				DBSystemName:     "elasticsearch",
				DBOperationName:  "search",
				DBCollectionName: index,
			},
		}
	}

	t.Run("reports the cluster name", func(t *testing.T) {
		span := esSpan("", "8b3f5a1c9d2e4f6a")
		attrs := AttrsToMap(TraceAttributesSelector(span, map[attr.Name]struct{}{}))
		v, ok := attrs.Get("db.namespace")
		require.True(t, ok)
		assert.Equal(t, "8b3f5a1c9d2e4f6a", v.Str())
		assert.Equal(t, "search 8b3f5a1c9d2e4f6a", span.TraceName())
	})

	t.Run("index wins over the cluster name in the span name", func(t *testing.T) {
		span := esSpan("my-index", "8b3f5a1c9d2e4f6a")
		attrs := AttrsToMap(TraceAttributesSelector(span, map[attr.Name]struct{}{}))
		v, ok := attrs.Get("db.namespace")
		require.True(t, ok)
		assert.Equal(t, "8b3f5a1c9d2e4f6a", v.Str())
		assert.Equal(t, "search my-index", span.TraceName())
	})

	t.Run("omitted when the response did not identify the cluster", func(t *testing.T) {
		span := esSpan("", "")
		attrs := AttrsToMap(TraceAttributesSelector(span, map[attr.Name]struct{}{}))
		_, ok := attrs.Get("db.namespace")
		assert.False(t, ok)
		assert.Equal(t, "search es:9200", span.TraceName())
	})

	t.Run("names the server as server.address does", func(t *testing.T) {
		resolved := esSpan("", "")
		resolved.Host = "172.18.0.2"
		resolved.HostName = "opensearchserver"

		requested := esSpan("", "")
		requested.Host = "172.18.0.2"
		requested.Statement = "http" + request.SchemeHostSeparator + "search.internal"

		requestedWithPort := esSpan("", "")
		requestedWithPort.Host = "172.18.0.2"
		requestedWithPort.Statement = "http" + request.SchemeHostSeparator + "opensearchserver:9200"

		for _, span := range []*request.Span{resolved, requested} {
			attrs := AttrsToMap(TraceAttributesSelector(span, map[attr.Name]struct{}{}))
			address, ok := attrs.Get("server.address")
			require.True(t, ok)
			assert.NotEqual(t, "172.18.0.2", address.Str())
			assert.Equal(t, "search "+address.Str()+":9200", span.TraceName())
		}
	})

	t.Run("does not repeat the port the Host header carries", func(t *testing.T) {
		span := esSpan("", "")
		span.Host = "172.18.0.2"
		span.Statement = "http" + request.SchemeHostSeparator + "opensearchserver:9200"
		assert.Equal(t, "search opensearchserver:9200", span.TraceName())
	})
}

func TestElasticsearchSpanNameWithoutOperation(t *testing.T) {
	esSpan := func(index string) *request.Span {
		return &request.Span{
			Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeElasticsearch,
			Elasticsearch: &request.Elasticsearch{
				DBSystemName:     "opensearch",
				DBCollectionName: index,
			},
		}
	}

	assert.Equal(t, "my-index", esSpan("my-index").TraceName())
	assert.Equal(t, "opensearch", esSpan("").TraceName())
}

func TestSQLPPSpanNameUsesServerAddress(t *testing.T) {
	span := &request.Span{
		Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeSQLPP,
		Method: "SELECT", Host: "10.1.2.3", HostName: "couchbase", HostPort: 8093,
		DBSystem: "couchbase",
	}
	attrs := AttrsToMap(TraceAttributesSelector(span, map[attr.Name]struct{}{}))
	address, ok := attrs.Get("server.address")
	require.True(t, ok)
	assert.Equal(t, "couchbase", address.Str())
	assert.Equal(t, "SELECT couchbase:8093", span.TraceName())

	span.Method = ""
	assert.Equal(t, "couchbase:8093", span.TraceName())
}
