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

// tpinjector has two BPF specs: the main tpinjector (spec 0) and the sock iterator (spec 1).
const expectedSpecCount = 2

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
			name:                "all",
			contextPropagation:  "all",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 3, // k_inject_http_headers | k_inject_tcp_options
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

			bundles, err := New(cfg).LoadSpecs()
			require.NoError(t, err)
			require.Len(t, bundles, expectedSpecCount, "tpinjector bundle count must match")

			// Spec 0 (tpinjector) carries the main constants.
			c := bundles[0].Constants

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

			// Spec 1 (sock_iter) carries only the debug flag.
			iterC := bundles[1].Constants
			_, ok = iterC["g_bpf_debug"]
			assert.True(t, ok, "iter g_bpf_debug should be present")
			assert.Len(t, iterC, 1, "iter spec should have only g_bpf_debug")
		})
	}
}
