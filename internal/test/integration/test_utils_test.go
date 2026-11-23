// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestTestComponentsReadyWaitsForTargetService(t *testing.T) {
	var targetReported atomic.Bool
	var healthy atomic.Bool
	healthy.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/query" {
			if !healthy.Load() {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writer.WriteHeader(http.StatusOK)
			return
		}

		result := `[]`
		if request.URL.Query().Get("query") != `http_server_request_duration_seconds_count{service_name="target-service"}` {
			// A broad query would find an unrelated service's series and incorrectly report readiness.
			result = `[{"metric":{"service_name":"unrelated-service"},"value":[0,"1"]}]`
		} else if targetReported.Load() {
			result = `[{"metric":{"service_name":"target-service"},"value":[0,"1"]}]`
		}
		_, _ = writer.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":` + result + `}}`))
	}))
	defer server.Close()

	pq := promtest.Client{HostPort: strings.TrimPrefix(server.URL, "http://")}
	ready, err := testComponentsReadyForService(server.URL, "target-service", &pq)
	require.NoError(t, err)
	require.False(t, ready, "an unrelated service's series must not satisfy readiness")

	healthy.Store(false)
	ready, err = testComponentsReadyForService(server.URL, "target-service", &pq)
	require.Error(t, err)
	require.False(t, ready, "an unhealthy endpoint must not satisfy readiness")
	healthy.Store(true)

	targetReported.Store(true)
	ready, err = testComponentsReadyForService(server.URL, "target-service", &pq)
	require.NoError(t, err)
	require.True(t, ready, "the target service's series should satisfy readiness")
}
