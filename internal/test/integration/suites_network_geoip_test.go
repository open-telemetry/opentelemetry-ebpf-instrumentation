// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestNetwork_GeoIP(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-netolly-geoip.yml", path.Join(pathOutput, "test-suite-netolly-geoip.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	checkGeoIPFlows := func(query string) {
		pq := promtest.Client{HostPort: prometheusHostPort}
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`obi_network_flow_bytes_total` + query)
			require.NoError(ct, err)
			require.NotEmpty(ct, results)
		}, 4*testTimeout, 100*time.Millisecond)
	}

	checkGeoIPFlows(`{dst_asn="AS209",dst_country="US"}`)
	checkGeoIPFlows(`{src_asn="AS209",src_country="US"}`)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}
