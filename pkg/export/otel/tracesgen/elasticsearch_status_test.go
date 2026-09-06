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
