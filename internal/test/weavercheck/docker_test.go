// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDockerPS(t *testing.T) {
	out := strings.Join([]string{
		"aaa\tdocker.io/otel/opentelemetry-collector-contrib@sha256:abc\tsuite_default\t",
		"bbb\totel/opentelemetry-collector-contrib:0.161.0\thost\thttp://127.0.0.1:18888/metrics",
		"ccc\totel/weaver:v0.26.1\tsuite_default,other\t",
		"malformed line",
	}, "\n") + "\n"

	require.Equal(t, []runningContainer{
		{id: "aaa", image: "otel/opentelemetry-collector-contrib@sha256:abc", networks: []string{"suite_default"}, telemetryURL: defaultCollectorTelemetryURL},
		{id: "bbb", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"host"}, telemetryURL: "http://127.0.0.1:18888/metrics"},
		{id: "ccc", image: "otel/weaver:v0.26.1", networks: []string{"suite_default", "other"}, telemetryURL: defaultCollectorTelemetryURL},
	}, parseDockerPS(out))
}

func TestWithoutRegistryHost(t *testing.T) {
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("docker.io/otel/weaver:v0.26.1"))
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("localhost/otel/weaver:v0.26.1"))
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("registry.local:5000/otel/weaver:v0.26.1"))
	require.Equal(t, "otel/weaver:v0.26.1", withoutRegistryHost("otel/weaver:v0.26.1"))
	require.Equal(t, "prometheus/prometheus:v3", withoutRegistryHost("quay.io/prometheus/prometheus:v3"))
}

func TestCollectorsBesideWeaverKeepsOnlyCollectorsSharingANetwork(t *testing.T) {
	weaver := runningContainer{id: "weaver", image: "otel/weaver:v0.26.1", networks: []string{"suite_default"}}
	tap := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"suite_default"}}
	stale := runningContainer{id: "stale", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"old_run"}}
	other := runningContainer{id: "prometheus", image: "quay.io/prometheus/prometheus:v3", networks: []string{"suite_default"}}

	require.Equal(t, []runningContainer{tap}, collectorsBesideWeaver([]runningContainer{weaver, tap, stale, other}))
}

func TestCollectorsBesideWeaverOnHostNetworking(t *testing.T) {
	weaver := runningContainer{id: "weaver", image: "otel/weaver:v0.26.1", networks: []string{"host"}}
	tap := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"host"}}

	require.Equal(t, []runningContainer{tap}, collectorsBesideWeaver([]runningContainer{weaver, tap}))
}

func TestCollectorsBesideWeaverWithoutWeaver(t *testing.T) {
	collector := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"suite_default"}}

	require.Empty(t, collectorsBesideWeaver([]runningContainer{collector}))
}

func TestWeaverRunning(t *testing.T) {
	weaver := runningContainer{id: "weaver", image: "otel/weaver:v0.26.1", networks: []string{"suite_default"}}
	collector := runningContainer{id: "tap", image: "otel/opentelemetry-collector-contrib:0.161.0", networks: []string{"suite_default"}}

	require.True(t, weaverRunning([]runningContainer{collector, weaver}))
	require.False(t, weaverRunning([]runningContainer{collector}))
	require.False(t, weaverRunning(nil))
}

func TestRuntimeImageFindsTheScraperImage(t *testing.T) {
	image, err := runtimeImage(busyboxRuntimeImageKey)
	require.NoError(t, err)
	require.Contains(t, image, "busybox:")
	require.Contains(t, image, "@sha256:")
}

func TestRuntimeImageInIgnoresCommentsAndOtherKeys(t *testing.T) {
	imageList := "# Runtime image pins\nOTHER_IMAGE=golang:1.26\nBUSYBOX_IMAGE=docker.io/busybox:musl@sha256:abc\n"

	image, ok := runtimeImageIn(imageList, "BUSYBOX_IMAGE")
	require.True(t, ok)
	require.Equal(t, "docker.io/busybox:musl@sha256:abc", image)

	_, ok = runtimeImageIn(imageList, "MISSING_IMAGE")
	require.False(t, ok)
}
