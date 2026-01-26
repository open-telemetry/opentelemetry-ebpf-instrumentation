// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

func testPythonGraphQL(t *testing.T) {
	const (
		comm          = "python3.14"
		address       = "http://localhost:8381/graphql/"
		query         = `{"query": "query TestMe { testme }"}`
		operationName = "GraphQL query"
	)

	var tq jaeger.TracesQuery
	params := neturl.Values{}
	params.Add("service", comm)
	params.Add("operation", operationName)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	require.Eventually(t, func() bool {
		resp, err := http.Post(address, "application/json", bytes.NewBuffer([]byte(query)))
		if err != nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}

		resp, err = http.Get(fullJaegerURL)
		if err != nil {
			return false
		}
		if resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}

		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "graphql.operation.type", Type: "string", Value: "query"})
		if len(traces) < 1 {
			return false
		}
		lastTrace := traces[len(traces)-1]
		span := lastTrace.Spans[0]

		if operationName != span.OperationName {
			return false
		}

		tag, found := jaeger.FindIn(span.Tags, "graphql.operation.name")
		if !found || tag.Value != "TestMe" {
			return false
		}

		tag, found = jaeger.FindIn(span.Tags, "graphql.document")
		if !found || tag.Value != "query TestMe { testme }" {
			return false
		}
		return true
	}, testTimeout, 100*time.Millisecond, "Python GraphQL traces not found")
}
