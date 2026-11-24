// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestGenericTracerJavaAndNodeJSGating(t *testing.T) {
	t.Run("disabled Java and NodeJS gate constants and probes", func(t *testing.T) {
		cfg := obi.DefaultConfig
		cfg.EBPF.ContextPropagation = config.ContextPropagationAll
		cfg.Metrics.Features = export.FeatureAll
		cfg.Java.Enabled = false
		cfg.NodeJS.Enabled = false

		tracer := New(nil, &cfg, nil)
		consts := tracer.constants(1 << 20)
		assert.Equal(t, false, consts["g_bpf_java_http1_enabled"])
		assert.Equal(t, uint32(1), consts["java_http1_max_requests"])
		assert.Equal(t, uint64(0), consts["nodejs_runtime_metrics_enabled"])

		assert.NotContains(t, tracer.KProbes(), "sys_ioctl")
		uprobes := tracer.UProbes()
		assert.NotContains(t, uprobes, "node")
		assert.NotContains(t, uprobes, "libuv.so")
	})

	t.Run("enabled Java and NodeJS attach probes and runtime metrics constant", func(t *testing.T) {
		cfg := obi.DefaultConfig
		cfg.Metrics.Features = export.FeatureApplicationRuntime
		cfg.Java.Enabled = true
		cfg.NodeJS.Enabled = true

		tracer := New(nil, &cfg, nil)
		consts := tracer.constants(1 << 20)
		assert.Equal(t, uint64(1), consts["nodejs_runtime_metrics_enabled"])
		assert.Equal(t, uint32(1), consts["java_http1_max_requests"], "header propagation disabled keeps java_http1_max_requests=1")

		assert.Contains(t, tracer.KProbes(), "sys_ioctl")
		uprobes := tracer.UProbes()
		assert.Contains(t, uprobes, "node")
		assert.Contains(t, uprobes, "libuv.so")
	})
}
