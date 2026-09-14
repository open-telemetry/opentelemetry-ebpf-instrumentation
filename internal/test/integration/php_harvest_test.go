// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

type phpHarvestCase struct {
	name     string
	url      string
	path     string
	route    string
	service  string
	version  string
	argument string
}

func testPHPHarvestedRoutes(t *testing.T) {
	tests := []phpHarvestCase{
		{
			name: "Laravel", url: "http://localhost:8082", path: "/api/echo/laravel",
			route: "/api/echo/laravel", service: "obi/php-harvest-laravel", version: "1.1.0", argument: "laravel",
		},
		{
			name: "Symfony", url: "http://localhost:8083", path: "/api/symfony/echo/symfony",
			route: "/api/symfony/echo/symfony", service: "obi/php-harvest-symfony", version: "2.2.0", argument: "symfony",
		},
		{
			name: "Slim", url: "http://localhost:8084", path: "/slim/api/echo/slim",
			route: "/slim/api/echo/slim", service: "obi/php-harvest-slim", version: "3.3.0", argument: "slim",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			waitForTestComponentsSub(t, test.url, test.path)
			requestPHPHarvestRoute(t, test)
			assertPHPHarvestedMetric(t, test)
			assertPHPHarvestedTrace(t, test)
		})
	}
}

func requestPHPHarvestRoute(t *testing.T, test phpHarvestCase) {
	for range 4 {
		response, err := http.Get(test.url + test.path)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)

		var body struct {
			Value string `json:"value"`
		}
		require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
		require.NoError(t, response.Body.Close())
		assert.Equal(t, test.argument, body.Value)
	}
}

func assertPHPHarvestedMetric(t *testing.T, test phpHarvestCase) {
	prometheus := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		results, err := prometheus.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`service_name="` + test.service + `",` +
			`service_version="` + test.version + `",` +
			`http_route="` + test.route + `"}`)
		require.NoError(collect, err)
		enoughPromResults(collect, results)
	}, testTimeout, 100*time.Millisecond)
}

func assertPHPHarvestedTrace(t *testing.T, test phpHarvestCase) {
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		trace, err := latestTraceMatching(test.service, func(trace jaeger.Trace) bool {
			return traceHasSpanTags(trace,
				jaeger.Tag{Key: "url.path", Type: "string", Value: test.path},
				jaeger.Tag{Key: "http.route", Type: "string", Value: test.route},
			)
		})
		require.NoError(collect, err)
		require.NotEmpty(collect, trace.TraceID)
	}, testTimeout, 100*time.Millisecond)
}
