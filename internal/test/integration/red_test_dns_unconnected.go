// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// Served by the compose network's embedded DNS, so no upstream resolver is involved
const unconnectedDNSName = "valkey."

// The question name carried by the workload's decoy UDP payload. It is only ever
// sent to a non-DNS port, so a lookup reported for this name means unrelated
// traffic was classified as DNS.
const falsePositiveDNSName = "falsepositive.test."

// The Redis traffic that follows each lookup. Instrumenting it confirms the
// workload is being watched, so a missing DNS metric means the lookup was not
// captured rather than that the process was never instrumented.
func testDNSUnconnectedResolverControl(t *testing.T, namespace string) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_system_name="redis",` +
			`service_namespace="` + namespace + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.LessOrEqual(ct, 1, totalPromCount(ct, results))
	}, testTimeout, 100*time.Millisecond)
}

func dnsLookupCount(ct *assert.CollectT, pq promtest.Client, namespace string) int {
	results, err := pq.Query(`dns_lookup_duration_seconds_count{` +
		`dns_question_name="` + unconnectedDNSName + `",` +
		`service_namespace="` + namespace + `"}`)
	require.NoError(ct, err)
	enoughPromResults(ct, results)
	return totalPromCount(ct, results)
}

// The Alpine workload resolves over an unconnected UDP socket, so the lookup is
// only recognizable as DNS through msg_name. Unclassified, no span is produced
// and the metric never appears for this name.
func testDNSMetricsForUnconnectedResolver(t *testing.T, namespace string) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// Eventually, Prometheus would make this query visible
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.LessOrEqual(ct, 1, dnsLookupCount(ct, pq, namespace))
	}, testTimeout, 100*time.Millisecond)
}

// Every iteration resolves the same name, so consecutive lookups are separated
// only by their transaction ids: reported as 0 they share a pairing key, and
// each lookup is discarded as a duplicate of the one still cached. Counting has
// to keep pace with the workload, which it cannot do while they collide.
func testDNSMetricsCountEveryLookup(t *testing.T, namespace string) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	var start int
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		start = dnsLookupCount(ct, pq, namespace)
		assert.Positive(ct, start)
	}, testTimeout, 100*time.Millisecond)

	// The workload resolves once a second, so a healthy pairing counts roughly
	// one lookup per second; colliding keys cap it at one per DNS request
	// timeout, which is 5s by default.
	const minLookups = 20

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.GreaterOrEqual(ct, dnsLookupCount(ct, pq, namespace)-start, minLookups)
	}, testTimeout, time.Second)
}

// The workload pairs every lookup with a decoy UDP exchange on an unconnected
// socket: a DNS-shaped payload, a receive that names no peer, and a non-DNS peer
// port. Classifying an answer by the socket it arrived on has to stop short of
// this, or unrelated UDP shows up as DNS telemetry.
func testDNSNoFalsePositiveFromNonDNSUDP(t *testing.T, namespace string) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// The decoy exchange follows each lookup in the same iteration, so several
	// reported lookups mean several decoy exchanges have been seen and had every
	// chance to be misreported.
	const lookupsBeforeChecking = 5

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.LessOrEqual(ct, lookupsBeforeChecking, dnsLookupCount(ct, pq, namespace))
	}, testTimeout, 100*time.Millisecond)

	// Every name, rather than just the decoy's own: a false positive reported
	// under any other name still means unrelated UDP became DNS telemetry.
	results, err := pq.Query(`dns_lookup_duration_seconds_count{` +
		`service_namespace="` + namespace + `"}`)
	require.NoError(t, err)
	require.NotEmpty(t, results, "no DNS lookups at all, so this proves nothing")

	for _, result := range results {
		assert.Equal(t, unconnectedDNSName, result.Metric["dns_question_name"],
			"non-DNS UDP on an unconnected socket was reported as a DNS lookup; "+
				"the decoy payload carries the name %q", falsePositiveDNSName)
	}
}

func testDNSUnconnectedResolver(t *testing.T) {
	testDNSUnconnectedResolverControl(t, "integration-test")
	testDNSMetricsForUnconnectedResolver(t, "integration-test")
}

func testDNSNoFalsePositive(t *testing.T) {
	testDNSNoFalsePositiveFromNonDNSUDP(t, "integration-test")
}

func testDNSEveryLookupCounted(t *testing.T) {
	testDNSMetricsCountEveryLookup(t, "integration-test")
}
