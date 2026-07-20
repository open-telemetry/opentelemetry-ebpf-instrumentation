// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Must match the marker messages emitted by the gokafka-seg test server.
const (
	kafkaTPURL                = "http://localhost:8389"
	kafkaTPContainerImage     = "hatest-testserver-go-kafka-traceparent"
	kafkaTPPositiveControlMsg = "kafka-tp-positive-control"
	kafkaTPAfterProduceMsg    = "kafka-tp-after-produce"
	// Fixed W3C traceparent injected on the request so the in-handler line is
	// enriched with a known trace_id.
	kafkaTPTraceID = "11112222333344445555666677778888"
	kafkaTPSpanID  = "1234567890abcdef"
)

// testGoKafkaTraceparent is a regression test for issue #2046: a stale Kafka
// produce traceparent must not leak into later work on the reused goroutine.
//
// /traceparent_probe logs once from the request goroutine (which carries the
// injected HTTP-server trace context: positive control, proves the log enricher
// is active) and once from a worker goroutine after a Kafka produce. The worker
// has no request context of its own, so its line must not be enriched. Before the
// fix, casgstatus re-installs the stale goroutine-keyed traceparent and the
// worker line inherits the produce's trace_id.
func testGoKafkaTraceparent(t *testing.T) {
	waitForTestComponentsNoMetrics(t, kafkaTPURL+"/smoke")

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	traceparent := fmt.Sprintf("00-%s-%s-01", kafkaTPTraceID, kafkaTPSpanID)
	fire := func() {
		req, reqErr := http.NewRequest(http.MethodGet, kafkaTPURL+"/traceparent_probe", nil)
		if reqErr != nil {
			return
		}
		req.Header.Set("traceparent", traceparent)
		if resp, doErr := http.DefaultClient.Do(req); doErr == nil {
			resp.Body.Close()
		}
	}

	// Gate on the enricher being provably active: the in-handler line must be
	// enriched with the injected trace_id, otherwise the absence check below
	// could pass vacuously.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		fire()
		containerID := testContainerID(ct, cl, kafkaTPContainerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		enriched := 0
		for _, line := range containerLogs(ct, cl, containerID) {
			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if fields["message"] == kafkaTPPositiveControlMsg && fields["trace_id"] == kafkaTPTraceID {
				enriched++
			}
		}
		assert.Positive(ct, enriched, "log enricher has not enriched the in-handler line yet")
	}, 2*testTimeout, time.Second)

	// Contamination is timing-dependent, so drive a batch to give a buggy build
	// many opportunities to leak the produce trace context into the worker line.
	const batch = 60
	for i := 0; i < batch; i++ {
		fire()
		time.Sleep(30 * time.Millisecond)
	}

	// Wait for the worker lines to flush, then count how many leaked a trace
	// context (the count is monotonic, so it is safe to assert once flushed).
	var contaminated, afterProduce int
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		containerID := testContainerID(ct, cl, kafkaTPContainerImage)
		if !assert.NotEmpty(ct, containerID) {
			return
		}
		contaminated, afterProduce = 0, 0
		for _, line := range containerLogs(ct, cl, containerID) {
			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if fields["message"] == kafkaTPAfterProduceMsg {
				afterProduce++
				if fields["trace_id"] != "" {
					contaminated++
				}
			}
		}
		assert.GreaterOrEqual(ct, afterProduce, batch, "waiting for worker log lines to flush")
	}, 2*testTimeout, time.Second)

	require.Zero(t, contaminated,
		"%d of %d worker log lines leaked a Kafka produce trace_id after the produce ended (issue #2046)",
		contaminated, afterProduce)
}
