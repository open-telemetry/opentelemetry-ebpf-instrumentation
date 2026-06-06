// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

func vtNestedTraces(ct *assert.CollectT) (total, nested int) {
	resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fsync-client&limit=1000")
	require.NoError(ct, err)
	if resp == nil {
		return 0, 0
	}
	defer resp.Body.Close()
	require.Equal(ct, http.StatusOK, resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/sync-client"})
	for _, tr := range traces {
		if len(tr.FindByOperationName("GET /rolldice/1", "client")) > 0 {
			nested++
		}
	}
	return len(traces), nested
}

// Virtual threads break tid-keyed correlation only under carrier contention:
// sequential requests pass even on a broken build, so the load must be
// concurrent and the assertion a ratio over many traces.
func TestJavaVirtualThreads(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-vthreads.yml", path.Join(pathOutput, "test-suite-java-vthreads.log"))
	require.NoError(t, err)

	require.NoError(t, compose.Up())

	// Sequential requests correlate even without the virtual-thread fix, so a
	// nested client span here only proves the pipeline (discovery, agent
	// injection, export) is up, without driving concurrent load early whose
	// broken traces would pollute the measured ratio below.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:8085/sync-client?url=http://downstream:8086/rolldice/1")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		_ = resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		_, nested := vtNestedTraces(ct)
		require.GreaterOrEqual(ct, nested, 1, "no nested trace exported yet")
	}, 3*time.Minute, 2*time.Second)

	var total, nested int
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var wg sync.WaitGroup
		for w := 0; w < 40; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 3; i++ {
					resp, err := http.Get("http://localhost:8085/sync-client?url=http://downstream:8086/rolldice/1")
					if err == nil {
						_ = resp.Body.Close()
					}
				}
			}()
		}
		wg.Wait()

		total, nested = vtNestedTraces(ct)
		require.GreaterOrEqual(ct, total, 60)
		require.GreaterOrEqual(ct, nested*10, total*8,
			"expected at least 80% of virtual-thread server traces to contain their own nested client span")
	}, 3*time.Minute, 10*time.Second)
	t.Logf("virtual-thread nested-trace ratio: %d/%d", nested, total)

	require.NoError(t, compose.Close())
}
