// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

func allEnabledMapPruneOptions() MapPruneOptions {
	return MapPruneOptions{
		ContextPropagationEnabled: true,
		HeaderPropagationEnabled:  true,
		TrackRequestHeaders:       true,
		PopulateTraceContext:      true,
		NodeJSEnabled:             true,
		NodeJSManualSpans:         true,
		JavaEnabled:               true,
		LargeBuffersEnabled:       true,
		AppRuntimeMetricsEnabled:  true,
		ExceptionsEnabled:         true,
		GoChannelLinksEnabled:     true,
		GoManualSDKEnabled:        true,
		Protocols: instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
			instrumentations.InstrumentationALL,
		}),
	}
}

func TestShrinkDisabledFeatureMapsAllEnabledIsNoOp(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"exception_events":            {Type: ebpf.RingBuf, MaxEntries: 1 << 18, Pinning: ebpfconvenience.PinInternal},
			"traces_ctx_v1":               {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpf.PinByName},
			"span_mem":                    {Type: ebpf.PerCPUArray, MaxEntries: 2, ValueSize: 4096},
			"go_auto_activation_attempts": {Type: ebpf.Hash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
			"ongoing_kafka_requests":      {Type: ebpf.LRUHash, MaxEntries: 10000},
		},
	}

	ShrinkDisabledFeatureMaps(spec, allEnabledMapPruneOptions())

	assert.Equal(t, uint32(1<<18), spec.Maps["exception_events"].MaxEntries)
	assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps["exception_events"].Pinning)
	assert.Equal(t, uint32(10000), spec.Maps["traces_ctx_v1"].MaxEntries)
	assert.Equal(t, ebpf.PinByName, spec.Maps["traces_ctx_v1"].Pinning)
	assert.Equal(t, ebpf.PerCPUArray, spec.Maps["span_mem"].Type)
	assert.Equal(t, uint32(2), spec.Maps["span_mem"].MaxEntries)
	assert.Equal(t, uint32(30000), spec.Maps["go_auto_activation_attempts"].MaxEntries)
	assert.Equal(t, uint32(10000), spec.Maps["ongoing_kafka_requests"].MaxEntries)
}

func TestShrinkDisabledFeatureMapsPinningAndTypeSemantics(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"exception_events":             {Type: ebpf.RingBuf, MaxEntries: 1 << 18, Pinning: ebpfconvenience.PinInternal},
			"traces_ctx_v1":                {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpf.PinByName},
			"span_mem":                     {Type: ebpf.PerCPUArray, MaxEntries: 2, ValueSize: 4096},
			"go_auto_activation_attempts":  {Type: ebpf.Hash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
			"msg_buffer_mem":               {Type: ebpf.PerCPUArray, MaxEntries: 1, ValueSize: 8192, Pinning: ebpfconvenience.PinInternal},
			"http1_header_buf_storage":     {Type: ebpf.PerCPUArray, MaxEntries: 1, ValueSize: 512},
			"go_http1_header_scan_storage": {Type: ebpf.PerCPUArray, MaxEntries: 1, ValueSize: 512},
			"ongoing_http":                 {Type: ebpf.LRUHash, MaxEntries: 10000},
			"ongoing_tcp_req":              {Type: ebpf.LRUHash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
			"ongoing_kafka_requests":       {Type: ebpf.LRUHash, MaxEntries: 10000},
			"go_grpc_client_conns":         {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
		},
	}

	opts := MapPruneOptions{
		Protocols: instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		}),
	}
	ShrinkDisabledFeatureMaps(spec, opts)

	assert.Equal(t, uint32(os.Getpagesize()), spec.Maps["exception_events"].MaxEntries)
	assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps["exception_events"].Pinning, "PinInternal must be preserved on shrunk RingBuf")

	assert.Equal(t, uint32(1), spec.Maps["traces_ctx_v1"].MaxEntries)
	assert.Equal(t, ebpf.PinNone, spec.Maps["traces_ctx_v1"].Pinning, "PinByName must be detached when traces_ctx_v1 is shrunk")

	assert.Equal(t, ebpf.Array, spec.Maps["span_mem"].Type)
	assert.Equal(t, uint32(2), spec.Maps["span_mem"].MaxEntries, "PerCPUArray conversion must preserve MaxEntries")
	assert.Equal(t, uint32(4096), spec.Maps["span_mem"].ValueSize)
	assert.Equal(t, uint32(1), spec.Maps["go_auto_activation_attempts"].MaxEntries)

	assert.Equal(t, ebpf.Array, spec.Maps["msg_buffer_mem"].Type)
	assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps["msg_buffer_mem"].Pinning)

	assert.Equal(t, ebpf.PerCPUArray, spec.Maps["http1_header_buf_storage"].Type)
	assert.Equal(t, ebpf.PerCPUArray, spec.Maps["go_http1_header_scan_storage"].Type)

	assert.Equal(t, uint32(10000), spec.Maps["ongoing_http"].MaxEntries)
	assert.Equal(t, uint32(30000), spec.Maps["ongoing_tcp_req"].MaxEntries, "FastCGI and mid-connection HTTP/2 detection require ongoing_tcp_req")
	assert.Equal(t, uint32(1), spec.Maps["ongoing_kafka_requests"].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps["go_grpc_client_conns"].MaxEntries)
}

func TestShrinkDisabledFeatureMapsGRPCKeptWhenHeaderPropagationEnabled(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"go_grpc_client_conns":         {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
			"grpc_h2_owned_streams":        {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
			"ongoing_grpc_client_requests": {Type: ebpf.LRUHash, MaxEntries: 10000},
		},
	}

	ShrinkDisabledFeatureMaps(spec, MapPruneOptions{
		ContextPropagationEnabled: true,
		HeaderPropagationEnabled:  true,
		Protocols: instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		}),
	})

	assert.Equal(t, uint32(10000), spec.Maps["go_grpc_client_conns"].MaxEntries)
	assert.Equal(t, uint32(10000), spec.Maps["grpc_h2_owned_streams"].MaxEntries)
	assert.Equal(t, uint32(10000), spec.Maps["ongoing_grpc_client_requests"].MaxEntries)
}

func TestShrinkDisabledFeatureMapsTCPReqShrunkForDNSOnly(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"ongoing_tcp_req":     {Type: ebpf.LRUHash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
			"ongoing_http2_grpc":  {Type: ebpf.LRUHash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
			"unconn_dns_socks":    {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
			"ongoing_sql_queries": {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
		},
	}

	ShrinkDisabledFeatureMaps(spec, MapPruneOptions{
		Protocols: instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
			instrumentations.InstrumentationDNS,
		}),
	})

	assert.Equal(t, uint32(1), spec.Maps["ongoing_tcp_req"].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps["ongoing_http2_grpc"].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps["ongoing_sql_queries"].MaxEntries)
	assert.Equal(t, uint32(10000), spec.Maps["unconn_dns_socks"].MaxEntries)
}

func TestShrinkDisabledFeatureMapsTracesCtxKeptForNodeJSManualSpans(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"traces_ctx_v1":          {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpf.PinByName},
			"node_manual_ctx_shadow": {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
		},
	}

	ShrinkDisabledFeatureMaps(spec, MapPruneOptions{
		NodeJSEnabled:     true,
		NodeJSManualSpans: true,
	})

	assert.Equal(t, uint32(10000), spec.Maps["traces_ctx_v1"].MaxEntries)
	assert.Equal(t, ebpf.PinByName, spec.Maps["traces_ctx_v1"].Pinning)
	assert.Equal(t, uint32(10000), spec.Maps["node_manual_ctx_shadow"].MaxEntries)
}

func TestShrinkDisabledFeatureMapsContextPropagationKeepsTCPAndHTTP2Guards(t *testing.T) {
	for _, instr := range []instrumentations.Instrumentation{
		instrumentations.InstrumentationDNS,
		instrumentations.InstrumentationSunRPC,
	} {
		spec := &ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{
				"ongoing_tcp_req":           {Type: ebpf.LRUHash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
				"ongoing_http2_connections": {Type: ebpf.LRUHash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
				"ongoing_http2_grpc":        {Type: ebpf.LRUHash, MaxEntries: 30000, Pinning: ebpfconvenience.PinInternal},
				"h2_cut_frames":             {Type: ebpf.LRUHash, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
			},
		}

		ShrinkDisabledFeatureMaps(spec, MapPruneOptions{
			ContextPropagationEnabled: true,
			Protocols: instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
				instr,
			}),
		})

		assert.Equal(t, uint32(30000), spec.Maps["ongoing_tcp_req"].MaxEntries, string(instr))
		assert.Equal(t, uint32(30000), spec.Maps["ongoing_http2_connections"].MaxEntries, string(instr))
		assert.Equal(t, uint32(30000), spec.Maps["ongoing_http2_grpc"].MaxEntries, string(instr))
		assert.Equal(t, uint32(10000), spec.Maps["h2_cut_frames"].MaxEntries, string(instr))
	}
}

func TestShrinkDisabledFeatureMapsIsIdempotentOnMultiSlotPerCPUArrays(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"span_mem":            {Type: ebpf.PerCPUArray, MaxEntries: 2, ValueSize: 4096},
			"java_http1_requests": {Type: ebpf.Array, MaxEntries: 10000, Pinning: ebpfconvenience.PinInternal},
		},
	}

	ShrinkDisabledFeatureMaps(spec, MapPruneOptions{})
	ShrinkDisabledFeatureMaps(spec, MapPruneOptions{})

	assert.Equal(t, ebpf.Array, spec.Maps["span_mem"].Type)
	assert.Equal(t, uint32(2), spec.Maps["span_mem"].MaxEntries, "repeated pruning must preserve multi-slot PerCPUArray MaxEntries")
	assert.Equal(t, uint32(1), spec.Maps["java_http1_requests"].MaxEntries)
}
