// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf_test

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestSharedMapsAcrossTracersArePinnedAndCompatible(t *testing.T) {
	assertSharedMapsCompatible(t, nil)
}

func TestSharedMapsCompatibleAfterFeaturePruning(t *testing.T) {
	profiles := []struct {
		name string
		cfg  func() *obi.Config
	}{
		{
			name: "metrics_only_default",
			cfg: func() *obi.Config {
				c := obi.DefaultConfig
				c.Prometheus.Port = 9090
				return &c
			},
		},
		{
			name: "traces_enabled",
			cfg: func() *obi.Config {
				c := obi.DefaultConfig
				c.Traces.CommonEndpoint = "http://localhost:4318"
				return &c
			},
		},
		{
			name: "http_only",
			cfg: func() *obi.Config {
				c := obi.DefaultConfig
				c.Prometheus.Port = 9090
				c.Prometheus.Instrumentations = []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}
				return &c
			},
		},
		{
			name: "context_propagation_tcp_only",
			cfg: func() *obi.Config {
				c := obi.DefaultConfig
				c.Prometheus.Port = 9090
				c.EBPF.ContextPropagation = config.ContextPropagationTCP
				return &c
			},
		},
		{
			name: "java_nodejs_disabled_exceptions_enabled",
			cfg: func() *obi.Config {
				c := obi.DefaultConfig
				c.Prometheus.Port = 9090
				c.Java.Enabled = false
				c.NodeJS.Enabled = false
				c.Exceptions.Enabled = true
				c.Logs.Endpoint = "http://localhost:4318"
				return &c
			},
		},
		{
			name: "log_enricher_enabled",
			cfg: func() *obi.Config {
				c := obi.DefaultConfig
				c.Prometheus.Port = 9090
				c.EBPF.LogEnricher.Services = []config.LogEnricherServiceConfig{{}}
				return &c
			},
		},
		{
			name: "all_features_enabled",
			cfg: func() *obi.Config {
				c := obi.DefaultConfig
				c.Traces.CommonEndpoint = "http://localhost:4318"
				c.Prometheus.Port = 9090
				c.Metrics.Features = export.FeatureAll
				c.EBPF.ContextPropagation = config.ContextPropagationAll
				c.EBPF.TrackRequestHeaders = true
				c.EBPF.PopulateTraceContext = true
				c.EBPF.BufferSizes.HTTP = 4096
				c.NodeJS.ManualSpans = true
				c.Exceptions.Enabled = true
				c.Logs.Endpoint = "http://localhost:4318"
				return &c
			},
		},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			assertSharedMapsCompatible(t, tc.cfg())
		})
	}
}

func assertSharedMapsCompatible(t *testing.T, cfg *obi.Config) {
	t.Helper()

	genericSpec, err := generictracer.LoadBpf()
	require.NoError(t, err)
	goSpec, err := gotracer.LoadBpf()
	require.NoError(t, err)
	tpSpec, err := tpinjector.LoadBpf()
	require.NoError(t, err)

	specs := []struct {
		name  string
		spec  *ebpf.CollectionSpec
		prune bool
	}{
		{name: "generictracer", spec: genericSpec, prune: true},
		{name: "gotracer", spec: goSpec, prune: true},
		{name: "tpinjector", spec: tpSpec, prune: true},
	}

	if cfg == nil || cfg.EBPF.LogEnricher.Enabled() {
		logSpec, err := logenricher.LoadBpf()
		require.NoError(t, err)
		specs = append(specs, struct {
			name  string
			spec  *ebpf.CollectionSpec
			prune bool
		}{name: "logenricher", spec: logSpec, prune: false})
	}

	originalPrivatePerCPU := make(map[string]bool)
	for _, s := range specs {
		for name, m := range s.spec.Maps {
			if m.Type == ebpf.PerCPUArray && m.Pinning == ebpf.PinNone {
				originalPrivatePerCPU[name] = true
			}
		}
	}

	if cfg != nil {
		opts := cfg.MapPruneOptions()
		for _, s := range specs {
			if s.prune {
				ebpfcommon.ShrinkDisabledFeatureMaps(s.spec, opts)
			}
		}
	}

	type mapOccurrence struct {
		tracer string
		spec   *ebpf.MapSpec
	}

	byName := make(map[string][]mapOccurrence)
	for _, s := range specs {
		for name, m := range s.spec.Maps {
			if strings.HasPrefix(name, ".") {
				continue
			}
			// Private PerCPUArray scratch buffers stay private per tracer to avoid preemption
			// races between kprobes and uprobes (even when shrunk to Array for disabled features);
			// ProgramArray tail-call tables are per-ELF.
			if originalPrivatePerCPU[name] || m.Type == ebpf.PerCPUArray || m.Type == ebpf.ProgramArray {
				continue
			}
			byName[name] = append(byName[name], mapOccurrence{tracer: s.name, spec: m})
		}
	}

	for name, occurrences := range byName {
		if len(occurrences) < 2 {
			continue
		}

		first := occurrences[0]
		for _, occ := range occurrences {
			detachedTracesCtx := name == "traces_ctx_v1" && occ.spec.MaxEntries == 1 && occ.spec.Pinning == ebpf.PinNone
			assert.True(t,
				occ.spec.Pinning == ebpfconvenience.PinInternal || occ.spec.Pinning == ebpf.PinByName || detachedTracesCtx,
				"shared map %s in %s must be pinned (OBI_PIN_INTERNAL or LIBBPF_PIN_BY_NAME), got pinning=%d",
				name, occ.tracer, occ.spec.Pinning)
			assert.Equal(t, first.spec.Type, occ.spec.Type, "shared map %s type mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.KeySize, occ.spec.KeySize, "shared map %s key size mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.ValueSize, occ.spec.ValueSize, "shared map %s value size mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.MaxEntries, occ.spec.MaxEntries, "shared map %s max entries mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.Flags, occ.spec.Flags, "shared map %s flags mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.Pinning, occ.spec.Pinning, "shared map %s pinning mismatch (%s vs %s)", name, first.tracer, occ.tracer)
		}
	}
}
