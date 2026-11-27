// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestGoProbesAndActivationGatingByPruneOptions(t *testing.T) {
	prevSupports := supportsContextPropagationWithProbe
	prevIntegrity := ebpfcommon.IntegrityModeOverride
	t.Cleanup(func() {
		supportsContextPropagationWithProbe = prevSupports
		ebpfcommon.IntegrityModeOverride = prevIntegrity
	})
	ebpfcommon.IntegrityModeOverride = false
	supportsContextPropagationWithProbe = func(*slog.Logger) bool { return true }

	bin := executableIdentity{Dev: 5, Ino: 10}
	cfg := obi.DefaultConfig
	cfg.Prometheus.Port = 9090
	cfg.EBPF.ContextPropagation = config.ContextPropagationAll

	tracer := New(&ebpfcommon.IdentityPidsFilter{}, &cfg, nil)
	tracer.currentBinary = bin
	tracer.goAutoSDKActivationByExecutable[bin] = true
	tracer.embeddedSDKActivationByExecutable = map[executableIdentity]bool{bin: true}
	tracer.goChannelOffsetsByExecutable[bin] = true

	probes := tracer.GoProbes()
	assert.NotContains(t, probes, "go.opentelemetry.io/otel/internal/global.(*tracer).Start")
	assert.NotContains(t, probes, "go.opentelemetry.io/auto/sdk.(*tracer).Start")
	assert.False(t, tracer.goAutoSDKActivationProbesEnabled())
	assert.False(t, tracer.goEmbeddedSDKActivationProbesEnabled())
	assert.False(t, tracer.goChannelLinkProbesEnabled())

	// Vendored OverrideAppExportQueue with metrics-only config re-enables SDK and channel probes.
	tracer.SetMapPruneOptions(cfg.MapPruneOptionsForContext(true))
	probes = tracer.GoProbes()
	assert.Contains(t, probes, "go.opentelemetry.io/otel/internal/global.(*tracer).Start")
	assert.Contains(t, probes, "go.opentelemetry.io/auto/sdk.(*tracer).Start")
	assert.True(t, tracer.goAutoSDKActivationProbesEnabled())
	assert.True(t, tracer.goEmbeddedSDKActivationProbesEnabled())
	assert.True(t, tracer.goChannelLinkProbesEnabled())
}

func TestAllowPIDSkipsGoAutoSDKWhenManualSDKDisabled(t *testing.T) {
	startTimeCalls := 0
	tracer := activationLifecycleTestTracer(func(app.PID) (uint64, error) {
		startTimeCalls++
		return 100, nil
	})
	opts := ebpfcommon.MapPruneOptions{GoManualSDKEnabled: false}
	tracer.SetMapPruneOptions(opts)

	fileInfo := exec.New(exec.Init{Dev: 5, Ino: 10})
	tracer.AllowPID(123, 1, fileInfo)

	assert.Zero(t, startTimeCalls, "AllowPID must skip /proc/<pid>/stat read when GoManualSDKEnabled is false")
	assert.Empty(t, tracer.goAutoSDKTargets)
	assert.Empty(t, tracer.goAutoSDKActivationLinks)
}
