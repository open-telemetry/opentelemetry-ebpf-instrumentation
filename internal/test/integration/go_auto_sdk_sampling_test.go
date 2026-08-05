// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	autoSDKRootSampledHeader        = "X-OBI-Auto-SDK-Root-Sampled"
	autoSDKRootRecordingHeader      = "X-OBI-Auto-SDK-Root-Recording"
	autoSDKRemoteSampledHeader      = "X-OBI-Auto-SDK-Remote-Sampled"
	autoSDKRemoteRecordingHeader    = "X-OBI-Auto-SDK-Remote-Recording"
	autoSDKRemoteNotSampledHeader   = "X-OBI-Auto-SDK-Remote-Not-Sampled"
	autoSDKRemoteNotRecordingHeader = "X-OBI-Auto-SDK-Remote-Not-Recording"
)

type goAutoSDKSamplingState struct {
	root               bool
	rootRecording      bool
	remoteSampled      bool
	remoteRecording    bool
	remoteNotSampled   bool
	remoteNotRecording bool
}

func TestSuite_GoAutoSDKAlwaysOff(t *testing.T) {
	compose, err := docker.ComposeSuite(
		"docker-compose.yml",
		path.Join(pathOutput, "test-suite-go-auto-sdk-always-off.log"),
	)
	require.NoError(t, err)
	compose.Env = append(
		compose.Env,
		"OTEL_EBPF_EXECUTABLE_PATH=testserver",
		"OTEL_TRACES_SAMPLER=always_off",
	)
	require.NoError(t, compose.Up())

	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})
	t.Cleanup(func() {
		runWeaverValidation(t)
	})

	t.Run("unsampled spans feed metrics only", testGoAutoSDKAlwaysOff)
}

func testGoAutoSDKAlwaysOff(t *testing.T) {
	waitForTestComponents(t, instrumentedServiceStdURL)
	samplingState := requestGoAutoSDKSampling(t)
	assert.False(t, samplingState.root)
	assert.False(t, samplingState.rootRecording)
	assert.False(t, samplingState.remoteSampled)
	assert.False(t, samplingState.remoteRecording)
	assert.False(t, samplingState.remoteNotSampled)
	assert.False(t, samplingState.remoteNotRecording)

	pq := promtest.Client{HostPort: prometheusHostPort}
	expectedUnsampledOperations := []string{
		"auto-sdk-sampling-root",
		"auto-sdk-too-many-options",
		"auto-sdk-deep-context",
		"auto-sdk-oversized-span",
		"auto-sdk-renamed",
		"auto-sdk-service-graph-client",
		"auto-sdk-max-options-client",
		"auto-sdk-set-attributes-client",
		"auto-sdk-last-options",
		"auto-sdk-remote-unsampled-child",
		"auto-sdk-remote-sampled-child",
		"auto-sdk-deep-remote-unsampled-child",
		"auto-sdk-option-boundary-new-root",
		"auto-sdk-option-overflow-new-root",
		"auto-sdk-context-boundary-sampled-child",
		"auto-sdk-context-overflow-sampled-child",
		"lifecycle parent",
		"lifecycle sibling 1",
		"lifecycle sibling 2",
		"lifecycle new root",
		"lifecycle context after end",
	}
	const query = `traces_span_metrics_calls_total{` +
		`service_namespace="integration-test",` +
		`service_name="testserver",` +
		`span_name="auto-sdk-sampling-root",` +
		`span_kind="SPAN_KIND_CLIENT",` +
		`status_code="STATUS_CODE_ERROR"` +
		`}`

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(query)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.GreaterOrEqual(ct, totalPromCount(ct, results), 1)
	}, testTimeout, 100*time.Millisecond)

	const durationQuery = `traces_span_metrics_duration_seconds_sum{` +
		`service_namespace="integration-test",` +
		`service_name="testserver",` +
		`span_name="auto-sdk-sampling-root",` +
		`span_kind="SPAN_KIND_CLIENT",` +
		`status_code="STATUS_CODE_ERROR"` +
		`}`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(durationQuery)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		total := 0.0
		for _, result := range results {
			require.Len(ct, result.Value, 2)
			value, err := strconv.ParseFloat(fmt.Sprint(result.Value[1]), 64)
			require.NoError(ct, err)
			total += value
		}
		assert.InDelta(ct, 0.0001, total, 0.000000001)
	}, testTimeout, 100*time.Millisecond)

	for _, spanName := range expectedUnsampledOperations {
		t.Run(spanName+" feeds metrics", func(t *testing.T) {
			requireGoAutoSDKSpanMetric(t, spanName)
		})
	}

	const lastOptionsLabels = `service_namespace="integration-test",` +
		`service_name="testserver",` +
		`span_name="auto-sdk-last-options",` +
		`span_kind="SPAN_KIND_INTERNAL"`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`traces_span_metrics_calls_total{` + lastOptionsLabels + `}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.GreaterOrEqual(ct, totalPromCount(ct, results), 1)
	}, testTimeout, 100*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`traces_span_metrics_duration_seconds_sum{` + lastOptionsLabels + `}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		total := 0.0
		for _, result := range results {
			require.Len(ct, result.Value, 2)
			value, err := strconv.ParseFloat(fmt.Sprint(result.Value[1]), 64)
			require.NoError(ct, err)
			total += value
		}
		assert.GreaterOrEqual(ct, total, 0.0)
		assert.Less(ct, total, 1.0)
	}, testTimeout, 100*time.Millisecond)

	for _, server := range []string{"manual-remote", "manual-remote-max", "manual-remote-set"} {
		serviceGraphQuery := `traces_service_graph_request_client_seconds_count{` +
			`client="testserver",` +
			`server="` + server + `"` +
			`}`
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(serviceGraphQuery)
			require.NoError(ct, err)
			enoughPromResults(ct, results)
			assert.GreaterOrEqual(ct, totalPromCount(ct, results), 1)
		}, testTimeout, 100*time.Millisecond)
	}

	var queryErr error
	assert.Never(t, func() bool {
		for _, operation := range expectedUnsampledOperations {
			found, err := jaegerHasOperation("testserver", operation)
			if err != nil && queryErr == nil {
				queryErr = err
			}
			if found {
				return true
			}
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)
	require.NoError(t, queryErr)
}

func requestGoAutoSDKSampling(t *testing.T) goAutoSDKSamplingState {
	t.Helper()

	resp, err := http.Get(instrumentedServiceStdURL + "/auto-sdk-sampling")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	parseHeader := func(name string) bool {
		value := resp.Header.Get(name)
		require.NotEmpty(t, value, "missing sampling state header %s", name)
		sampled, err := strconv.ParseBool(value)
		require.NoError(t, err)
		return sampled
	}

	return goAutoSDKSamplingState{
		root:               parseHeader(autoSDKRootSampledHeader),
		rootRecording:      parseHeader(autoSDKRootRecordingHeader),
		remoteSampled:      parseHeader(autoSDKRemoteSampledHeader),
		remoteRecording:    parseHeader(autoSDKRemoteRecordingHeader),
		remoteNotSampled:   parseHeader(autoSDKRemoteNotSampledHeader),
		remoteNotRecording: parseHeader(autoSDKRemoteNotRecordingHeader),
	}
}

func requireGoAutoSDKSpanMetric(t *testing.T, spanName string) {
	t.Helper()

	pq := promtest.Client{HostPort: prometheusHostPort}
	query := `traces_span_metrics_calls_total{` +
		`service_namespace="integration-test",` +
		`service_name="testserver",` +
		`span_name="` + spanName + `"` +
		`}`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(query)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.GreaterOrEqual(ct, totalPromCount(ct, results), 1)
	}, testTimeout, 100*time.Millisecond)
}

func jaegerHasOperation(service, operation string) (bool, error) {
	params := url.Values{}
	params.Set("service", service)
	params.Set("operation", operation)

	resp, err := http.Get(jaegerQueryURL + "?" + params.Encode())
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("jaeger query returned status %d", resp.StatusCode)
	}

	var traces jaeger.TracesQuery
	if err := json.NewDecoder(resp.Body).Decode(&traces); err != nil {
		return false, err
	}

	for i := range traces.Data {
		if len(traces.Data[i].FindByOperationName(operation, "")) > 0 {
			return true, nil
		}
	}
	return false, nil
}
