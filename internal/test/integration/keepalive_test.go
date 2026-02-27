// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"net/http"
	"path"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestExistingSocketsDetection(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-keepalive.yml", path.Join(pathOutput, "test-suite-keepalive.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	waitForTestComponentsNoMetrics(t, "http://localhost:8080/smoke")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:9091/status")
		require.NoError(ct, err)
		defer resp.Body.Close()
		var status struct {
			TraceparentSeen bool `json:"traceparent_seen"`
		}
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&status))
		require.True(ct, status.TraceparentSeen)
	}, 2*time.Minute, time.Second)

	require.NoError(t, compose.Close())
}
