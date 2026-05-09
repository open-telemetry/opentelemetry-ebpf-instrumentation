// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obiconfigv2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

func TestDefaultConfigRoundTrip(t *testing.T) {
	doc, err := RuntimeToDocument(&obi.DefaultConfig)
	require.NoError(t, err)

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, got.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeout, got.ChannelSendTimeout)
	require.Equal(t, obi.DefaultConfig.EnforceSysCaps, got.EnforceSysCaps)
	require.Equal(t, obi.DefaultConfig.EBPF.WakeupLen, got.EBPF.WakeupLen)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchLength, got.EBPF.BatchLength)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchTimeout, got.EBPF.BatchTimeout)
	require.Equal(t, obi.DefaultConfig.EBPF.ContextPropagation, got.EBPF.ContextPropagation)
	require.Equal(t, obi.DefaultConfig.EBPF.TCBackend, got.EBPF.TCBackend)
	require.Equal(t, obi.DefaultConfig.EBPF.InstrumentCuda, got.EBPF.InstrumentCuda)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.Source, got.NetworkFlows.Source)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ListenInterfaces, got.NetworkFlows.ListenInterfaces)
	require.Equal(t, obi.DefaultConfig.NameResolver.CacheLen, got.NameResolver.CacheLen)
	require.Equal(t, obi.DefaultConfig.Attributes.Kubernetes.Enable, got.Attributes.Kubernetes.Enable)
	require.Equal(t, obi.DefaultConfig.Traces.QueueSize, got.Traces.QueueSize)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.OTELIntervalMS, got.OTELMetrics.OTELIntervalMS)
}

func TestRuntimeFilterAndGoFlagRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Discovery.SkipGoSpecificTracers = true
	cfg.Filters.Application = filter.AttributeFamilyConfig{
		"http_request_method": {Match: "GET"},
	}
	cfg.Filters.Network = filter.AttributeFamilyConfig{
		"src_name": {NotMatch: "loopback"},
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	require.Equal(t, false, nestedMap(doc.Extensions.OBI.Capture.Runtimes, "go")["enabled"])
	require.Equal(t, "GET", nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "http", "filters", "traces", "http_request_method")["match"])
	require.Equal(t, "loopback", nestedMap(doc.Extensions.OBI.Capture.Network, "capture", "filters", "metrics", "src_name")["not_match"])

	got, err := ConfigToRuntime(doc.Extensions.OBI, obiv2.DeploymentModeStandalone)
	require.NoError(t, err)

	require.True(t, got.Discovery.SkipGoSpecificTracers)
	require.Equal(t, cfg.Filters.Application, got.Filters.Application)
	require.Equal(t, cfg.Filters.Network, got.Filters.Network)
}
