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

func TestTracer_Constants_InjectFlags(t *testing.T) {
	tests := []struct {
		name                string
		contextPropagation  string
		expectedInjectFlags uint32
	}{
		{
			name:                "disabled",
			contextPropagation:  "disabled",
			expectedInjectFlags: 0, // neither HTTP headers nor TCP options
		},
		{
			name:                "headers only",
			contextPropagation:  "headers",
			expectedInjectFlags: 1, // k_inject_http_headers
		},
		{
			name:                "tcp only",
			contextPropagation:  "tcp",
			expectedInjectFlags: 2, // k_inject_tcp_options
		},
		{
			name:                "headers and tcp",
			contextPropagation:  "headers,tcp",
			expectedInjectFlags: 3, // k_inject_http_headers | k_inject_tcp_options
		},
		{
			name:                "ip only",
			contextPropagation:  "ip",
			expectedInjectFlags: 0, // tpinjector doesn't handle IP options
		},
		{
			name:                "all",
			contextPropagation:  "all",
			expectedInjectFlags: 3, // k_inject_http_headers | k_inject_tcp_options (IP handled by tctracer)
		},
		{
			name:                "tcp and ip",
			contextPropagation:  "tcp,ip",
			expectedInjectFlags: 2, // k_inject_tcp_options only (IP handled by tctracer)
		},
		{
			name:                "headers and ip",
			contextPropagation:  "headers,ip",
			expectedInjectFlags: 1, // k_inject_http_headers only (IP handled by tctracer)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &obi.Config{
				EBPF: config.EBPFTracer{
					MaxTransactionTime: 10 * time.Second,
				},
			}
			err := cfg.EBPF.ContextPropagation.UnmarshalText([]byte(tt.contextPropagation))
			require.NoError(t, err)

			tracer := New(cfg)
			constants := tracer.Constants()

			// Check that inject_flags is set correctly
			injectFlags, ok := constants["inject_flags"]
			assert.True(t, ok, "inject_flags should be present in constants")
			assert.Equal(t, tt.expectedInjectFlags, injectFlags, "inject_flags value mismatch")

			// Verify the logic
			expectedFlags := uint32(0)
			if cfg.EBPF.ContextPropagation.HasHeaders() {
				expectedFlags |= 1
			}
			if cfg.EBPF.ContextPropagation.HasTCP() {
				expectedFlags |= 2
			}
			assert.Equal(t, expectedFlags, injectFlags, "inject_flags should match expected calculation")
		})
	}
}

func TestTracer_Constants_FilterPids(t *testing.T) {
	tests := []struct {
		name              string
		bpfPidFilterOff   bool
		expectedFilterVal int32
	}{
		{
			name:              "filter enabled",
			bpfPidFilterOff:   false,
			expectedFilterVal: 1,
		},
		{
			name:              "filter disabled",
			bpfPidFilterOff:   true,
			expectedFilterVal: 0,
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

			tracer := New(cfg)
			constants := tracer.Constants()

			filterPids, ok := constants["filter_pids"]
			assert.True(t, ok, "filter_pids should be present in constants")
			assert.Equal(t, tt.expectedFilterVal, filterPids, "filter_pids value mismatch")
		})
	}
}
