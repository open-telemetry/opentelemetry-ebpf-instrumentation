// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestSuite_DjangoRoutes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-django.yml", filepath.Join(pathOutput, "test-suite-django.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())
	t.Cleanup(func() { runWeaverValidation(t) })

	const baseURL = "http://localhost:8381"
	waitForTestComponentsNoMetrics(t, baseURL+"/smoke/")
	client := &http.Client{
		Timeout: 5 * time.Second,
		// Inspect the original admin request, which redirects anonymous users to login.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(client.CloseIdleConnections)

	for _, tc := range []struct {
		path   string
		route  string
		status int
	}{
		{path: "/shop/orders/42/", route: "/shop/orders/<int:order_id>/", status: http.StatusOK},
		{path: "/wholesale/orders/123/", route: "/wholesale/orders/<int:order_id>/", status: http.StatusOK},
		{path: "/en/localized/orders/42/", route: "/<language>/localized/orders/<int:order_id>/", status: http.StatusOK},
		{path: "/de/localized/orders/123/", route: "/<language>/localized/orders/<int:order_id>/", status: http.StatusOK},
		{path: "/optional-language/orders/42/", route: "/optional-language/orders/<int:order_id>/", status: http.StatusOK},
		{path: "/de/optional-language/orders/123/", route: "/<language>/optional-language/orders/<int:order_id>/", status: http.StatusOK},
		{path: "/backoffice/login/", route: "/backoffice/login/", status: http.StatusOK},
		{path: "/backoffice/auth/user/add/", route: "/backoffice/<app_label>/<model_name>/add/", status: http.StatusFound},
		{path: "/backoffice/auth/user/42/change/", route: "/backoffice/<app_label>/<model_name>/<path:object_id>/change/", status: http.StatusFound},
		{path: "/backoffice/auth/user/part/42/history/", route: "/backoffice/<app_label>/<model_name>/<path:object_id>/history/", status: http.StatusFound},
		{path: "/backoffice/auth/user/42/delete/", route: "/backoffice/<app_label>/<model_name>/<path:object_id>/delete/", status: http.StatusFound},
		{path: "/backoffice/r/7/42/", route: "/backoffice/r/<path:content_type_id>/<path:object_id>/", status: http.StatusFound},
	} {
		t.Run(tc.path, func(t *testing.T) {
			pq := promtest.Client{HostPort: prometheusHostPort}
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				resp, err := client.Get(baseURL + tc.path)
				require.NoError(ct, err)
				_, readErr := io.Copy(io.Discard, resp.Body)
				require.NoError(ct, resp.Body.Close())
				require.NoError(ct, readErr)
				require.Equal(ct, tc.status, resp.StatusCode)

				query := fmt.Sprintf(`http_server_request_duration_seconds_count{service_name="django-testserver",http_request_method="GET",http_response_status_code="%d",http_route=%q,url_path=%q}`, tc.status, tc.route, tc.path)
				results, err := pq.Query(query)
				require.NoError(ct, err)
				require.NotEmpty(ct, results)
				assert.GreaterOrEqual(ct, totalPromCount(ct, results), 1)
			}, testTimeout, time.Second)
			assertDjangoRouteTrace(t, tc.path, tc.route, tc.status)
		})
	}
}

func assertDjangoRouteTrace(t *testing.T, requestPath, route string, status int) {
	t.Helper()
	operation := "GET " + route
	query := url.Values{"service": {"django-testserver"}, "operation": {operation}}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?" + query.Encode())
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var traces jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&traces))
		matches := traces.FindBySpan(
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
			jaeger.Tag{Key: "http.route", Type: "string", Value: route},
			jaeger.Tag{Key: "url.path", Type: "string", Value: requestPath},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(status)},
		)
		require.NotEmpty(ct, matches)
		assert.NotEmpty(ct, matches[0].FindByOperationName(operation, "server"))
	}, testTimeout, time.Second)
}
