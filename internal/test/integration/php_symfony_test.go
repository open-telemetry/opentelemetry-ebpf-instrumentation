// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	phpSymfonyURL            = "http://localhost:8081"
	phpSymfonyServiceName    = "obi/symfony-echo-api"
	phpSymfonyServiceVersion = "1.2.3"
)

func testPHPSymfony(t *testing.T) {
	waitForTestComponentsSub(t, phpSymfonyURL, "/api/echo/ready")

	for range 4 {
		resp, err := http.Get(phpSymfonyURL + "/api/echo/metadata")
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + phpSymfonyServiceName + `",` +
			`service_version="` + phpSymfonyServiceVersion + `",` +
			`url_path="/api/echo/metadata"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
	}, testTimeout, 100*time.Millisecond)
}
