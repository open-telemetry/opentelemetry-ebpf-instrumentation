// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

// tpinjector has a single BPF spec; all constants live in spec 0.
const expectedSpecCount = 1

func TestTracer_Constants(t *testing.T) {
	tests := []struct {
		name                string
		contextPropagation  string
		bpfPidFilterOff     bool
		expectedInjectFlags uint32
		expectedFilterPids  int32
	}{
		{
			name:                "all disabled, filter on",
			contextPropagation:  "disabled",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 0,
			expectedFilterPids:  1,
		},
		{
			name:                "headers only",
			contextPropagation:  "headers",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 1, // k_inject_http_headers
			expectedFilterPids:  1,
		},
		{
			name:                "tcp only",
			contextPropagation:  "tcp",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 2, // k_inject_tcp_options
			expectedFilterPids:  1,
		},
		{
			name:                "headers and tcp",
			contextPropagation:  "headers,tcp",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 3, // k_inject_http_headers | k_inject_tcp_options
			expectedFilterPids:  1,
		},
		{
			name:                "ip only (handled by tctracer)",
			contextPropagation:  "ip",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 0,
			expectedFilterPids:  1,
		},
		{
			name:                "all",
			contextPropagation:  "all",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 3, // k_inject_http_headers | k_inject_tcp_options; IP handled by tctracer
			expectedFilterPids:  1,
		},
		{
			name:                "filter off",
			contextPropagation:  "disabled",
			bpfPidFilterOff:     true,
			expectedInjectFlags: 0,
			expectedFilterPids:  0,
		},
		{
			name:                "headers, filter off",
			contextPropagation:  "headers",
			bpfPidFilterOff:     true,
			expectedInjectFlags: 1,
			expectedFilterPids:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &obi.Config{
				Discovery: services.DiscoveryConfig{
					BPFPidFilterOff: tt.bpfPidFilterOff,
				},
				EBPF: config.EBPFTracer{
					MaxTransactionTime: 10 * time.Second,
				},
			}
			err := cfg.EBPF.ContextPropagation.UnmarshalText([]byte(tt.contextPropagation))
			require.NoError(t, err)

			constants := New(cfg).Constants()
			require.Len(t, constants, expectedSpecCount, "tpinjector should have exactly one spec")

			// Spec 0 carries all constants for this tracer.
			c := constants[0]

			injectFlags, ok := c["inject_flags"]
			assert.True(t, ok, "inject_flags should be present")
			assert.Equal(t, tt.expectedInjectFlags, injectFlags)

			filterPids, ok := c["filter_pids"]
			assert.True(t, ok, "filter_pids should be present")
			assert.Equal(t, tt.expectedFilterPids, filterPids)

			_, ok = c["max_transaction_time"]
			assert.True(t, ok, "max_transaction_time should be present")

			_, ok = c["g_bpf_debug"]
			assert.True(t, ok, "g_bpf_debug should be present")
		})
	}
}
