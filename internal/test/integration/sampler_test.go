// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const (
	// service-c's sampler in configs/obi-config-sampler.yml. traceidratio is not
	// parent based: service-c decides by the trace id, whatever service-a decided.
	serviceCSamplingRatio = 0.5
	samplerTestRequests   = 20
)

// the traceparent service-d reports it was called with
var reportedTraceparent = regexp.MustCompile(`traceparent: 00-([0-9a-f]{32})-[0-9a-f]{16}-([0-9a-f]{2})`)

type propagatedDecision struct {
	traceID string
	sampled bool
}

// requestPropagatedDecision calls service-a, which calls service-c, which calls
// service-d, and returns the sampling decision service-c propagated to service-d
func requestPropagatedDecision(t require.TestingT) (propagatedDecision, bool) {
	resp, err := http.Get("http://localhost:5000/a")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	match := reportedTraceparent.FindStringSubmatch(string(body))
	if match == nil {
		return propagatedDecision{}, false
	}

	flags, err := strconv.ParseUint(match[2], 16, 8)
	require.NoError(t, err)

	return propagatedDecision{traceID: match[1], sampled: trace.TraceFlags(flags).IsSampled()}, true
}

func sampledByServiceC(t require.TestingT, traceID string) bool {
	id, err := trace.TraceIDFromHex(traceID)
	require.NoError(t, err)

	sampler := sdktrace.TraceIDRatioBased(serviceCSamplingRatio)

	return sampler.ShouldSample(sdktrace.SamplingParameters{TraceID: id}).Decision == sdktrace.RecordAndSample
}

func exportedServices(t require.TestingT, traceID string) map[string]bool {
	resp, err := getJaeger(jaegerQueryURL + "/" + traceID)
	require.NoError(t, err)
	defer resp.Body.Close()

	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

	services := map[string]bool{}
	for _, tr := range tq.Data {
		maps.Copy(services, traceServices(tr))
	}

	return services
}

func testSampler(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5000")
	waitForTestComponents(t, "http://localhost:5002")
	waitForTestComponents(t, "http://localhost:5003")

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	time.Sleep(60 * time.Second)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, ok := requestPropagatedDecision(ct)
		require.True(ct, ok, "service-d received no traceparent")
	}, testTimeout, time.Second)

	decisions := make([]propagatedDecision, 0, samplerTestRequests)
	for range samplerTestRequests {
		decision, ok := requestPropagatedDecision(t)
		require.True(t, ok, "service-d received no traceparent")
		decisions = append(decisions, decision)
	}

	// service-a samples every trace it starts, then service-c samples it again by
	// the trace id: what service-d receives must be service-c's decision
	sampled := 0
	for _, decision := range decisions {
		t.Logf("trace %s: service-d received sampled=%t", decision.traceID, decision.sampled)
		require.Equal(t, sampledByServiceC(t, decision.traceID), decision.sampled,
			"trace %s: service-c did not propagate its own sampling decision", decision.traceID)
		if decision.sampled {
			sampled++
		}
	}
	// with a 0.5 ratio, all 20 traces get the same decision once in half a million runs
	require.NotZero(t, sampled, "no trace was sampled: the test cannot show a propagated 01")
	require.NotEqual(t, len(decisions), sampled, "no trace was dropped: the test cannot show a propagated 00")

	// service-d, sampled as parentbased_always_on, exports only what service-c propagated as sampled
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, decision := range decisions {
			services := exportedServices(ct, decision.traceID)
			require.True(ct, services["service-a"], "trace %s has no service-a span", decision.traceID)
			if decision.sampled {
				require.True(ct, services["service-c"], "trace %s has no service-c span", decision.traceID)
				require.True(ct, services["service-d"], "trace %s has no service-d span", decision.traceID)
			}
		}
	}, testTimeout, 1500*time.Millisecond)

	// the sampled traces of the same requests are exported by now, so the
	// dropped ones are not just late
	for _, decision := range decisions {
		if decision.sampled {
			continue
		}
		services := exportedServices(t, decision.traceID)
		assert.False(t, services["service-c"], "trace %s: service-c exported a span it dropped", decision.traceID)
		assert.False(t, services["service-d"], "trace %s: service-d exported a span whose parent was dropped", decision.traceID)
	}
}

func TestSampler(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-sampler.yml", path.Join(pathOutput, "test-suite-sampler.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Sampler", testSampler)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}
