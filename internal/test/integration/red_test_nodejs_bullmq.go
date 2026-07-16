// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// The worker establishes its Redis connections before the agent attaches (the
// compose file orders the agent after the worker's healthcheck) and parks in a
// blocking BZPOPMIN, so the first traffic the agent sees on that connection is
// a spontaneous reply. Before the receive-first fix this lost every span on the
// blocking connection and leaked reversed server-side spans named after reply
// payloads.
func testREDMetricsNodeBullMQ(t *testing.T) {
	const url = "http://localhost:8382"

	// each job wakes the worker: bzpopmin reply + evalsha + get + set
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+"/job", 200)
		time.Sleep(500 * time.Millisecond)
	}

	pq := promtest.Client{HostPort: prometheusHostPort}
	// ioredis sends lowercase command words on the wire
	for _, op := range []string{"bzpopmin", "evalsha", "get", "set", "zadd"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + op + `",` +
				`service_namespace="integration-test"}`)
			require.NoError(ct, err, "failed to query prometheus for %s", op)
			enoughPromResults(ct, results)
			val := totalPromCount(ct, results)
			assert.LessOrEqual(ct, 3, val, "expected at least 3 %s operations, got %d", op, val)
		}, testTimeout, 100*time.Millisecond)
	}

	// reversed events used to surface as spans named after reply payload tokens
	results, err := pq.Query(`db_client_operation_duration_seconds_count{db_operation_name=~"job-.*|bullmq.*"}`)
	require.NoError(t, err)
	require.Empty(t, results, "found spans named after reply payloads: %v", results)

	spans := []TestCaseSpan{
		{
			Name: "bzpopmin",
			Attributes: []attribute.KeyValue{
				attribute.String("db.operation.name", "bzpopmin"),
			},
		},
		{
			Name: "evalsha",
			Attributes: []attribute.KeyValue{
				attribute.String("db.operation.name", "evalsha"),
				attribute.Bool("error", true),
				attribute.String("db.response.status_code", "NOSCRIPT"),
			},
		},
		{
			Name: "set",
			Attributes: []attribute.KeyValue{
				attribute.String("db.operation.name", "set"),
			},
		},
	}
	for i := range spans {
		spans[i].Attributes = append(spans[i].Attributes,
			attribute.String("db.system.name", "redis"),
			attribute.String("span.kind", "client"),
			attribute.Int("server.port", 6379),
		)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, span := range spans {
			resp, err := http.Get(jaegerQueryURL + "?service=node&operation=" + span.Name)
			require.NoError(ct, err, "failed to query jaeger for %s", span.Name)
			if resp == nil {
				return
			}
			require.Equal(ct, http.StatusOK, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(ct, 1, len(traces), "span %s with tags %v not found in traces %v", span.Name, tags, tq.Data)
		}
	}, testTimeout, 100*time.Millisecond)

	// the worker sets a ~3.8KB value per job; the payload tail can only reach
	// db.query.text through the TCP large-buffer path (inline capture is 256B)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=node&operation=set")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		found := false
		for _, trace := range tq.Data {
			for _, span := range trace.Spans {
				if tag, ok := jaeger.FindIn(span.Tags, "db.query.text"); ok {
					if text, isStr := tag.Value.(string); isStr &&
						len(text) > 3000 && strings.HasSuffix(text, "-tailmarker") {
						found = true
					}
				}
			}
		}
		assert.True(ct, found, "no set span carrying the full large-buffer payload")
	}, testTimeout, 100*time.Millisecond)
}

func waitForBullMQTestComponents(t *testing.T, url string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, url+"/health", nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// the idle worker emits a bzpopmin span per 5s park cycle once the agent
		// is attached; this doubles as the receive-first regression check, since
		// a reversed connection never produces them
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_operation_name="bzpopmin"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 2*time.Minute, time.Second)
}
