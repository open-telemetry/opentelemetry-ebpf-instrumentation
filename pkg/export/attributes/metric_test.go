// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Prometheus names below are part of OBI's public output. They are derived from each
// metric's OTEL name, Unit and Type, so a change to any of those three renames a published
// series: only update an expectation here as a deliberate rename.
func TestPrometheusNames(t *testing.T) {
	tests := []struct {
		metric Name
		prom   string
	}{
		{NetworkFlow, "obi_network_flow_bytes_total"},
		{NetworkFlowPackets, "obi_network_flow_packets_total"},
		{NetworkInterZone, "obi_network_inter_zone_bytes_total"},
		{HTTPServerRequestSize, "http_server_request_body_size_bytes"},
		{HTTPServerResponseSize, "http_server_response_body_size_bytes"},
		{HTTPClientRequestSize, "http_client_request_body_size_bytes"},
		{HTTPClientResponseSize, "http_client_response_body_size_bytes"},
		{HTTPServerDuration, "http_server_request_duration_seconds"},
		{HTTPClientDuration, "http_client_request_duration_seconds"},
		{RPCServerDuration, "rpc_server_call_duration_seconds"},
		{RPCClientDuration, "rpc_client_call_duration_seconds"},
		{DBClientDuration, "db_client_operation_duration_seconds"},
		{DBServerDuration, "db_server_operation_duration_seconds"},
		{MessagingPublishDuration, "messaging_client_operation_duration_seconds"},
		{MessagingProcessDuration, "messaging_process_duration_seconds"},
		{GPUCudaKernelLaunchCalls, "gpu_cuda_kernel_launch_calls_total"},
		{GPUCudaGraphLaunchCalls, "gpu_cuda_graph_launch_calls_total"},
		{GPUCudaKernelGridSize, "gpu_cuda_kernel_grid_size"},
		{GPUCudaKernelBlockSize, "gpu_cuda_kernel_block_size"},
		{GPUCudaMemoryAllocations, "gpu_cuda_memory_allocations_bytes_total"},
		{GPUCudaMemoryCopies, "gpu_cuda_memory_copies_bytes"},
		{DNSLookupDuration, "dns_lookup_duration_seconds"},
		{GenAIClientInputTokenUsage, "gen_ai_client_token_usage"},
		{GenAIClientOutputTokenUsage, "gen_ai_client_token_usage"},
		{GenAIClientOperationDuration, "gen_ai_client_operation_duration_seconds"},
		{GoRuntimeMemoryLimit, "go_memory_limit_bytes"},
		{GoRuntimeMemoryGCGoal, "go_memory_gc_goal_bytes"},
		{GoRuntimeMemoryGCCycles, "go_memory_gc_cycles_total"},
		{GoRuntimeMemoryGCPauseDuration, "go_memory_gc_pause_duration_seconds"},
		{GoRuntimeMemoryUsed, "go_memory_used_bytes"},
		{GoRuntimeMemoryAllocated, "go_memory_allocated_bytes_total"},
		{GoRuntimeMemoryAllocations, "go_memory_allocations_total"},
		{GoRuntimeCPUTime, "go_cpu_time_seconds_total"},
		{GoRuntimeGoroutineCount, "go_goroutine_count"},
		{GoRuntimeProcessorLimit, "go_processor_limit"},
		{GoRuntimeConfigGOGC, "go_config_gogc_percent"},
		{GoRuntimeScheduleDuration, "go_schedule_duration_seconds"},
		{JVMMemoryUsed, "jvm_memory_used_bytes"},
		{JVMMemoryCommitted, "jvm_memory_committed_bytes"},
		{JVMMemoryLimit, "jvm_memory_limit_bytes"},
		{JVMMemoryUsedAfterLastGC, "jvm_memory_used_after_last_gc_bytes"},
		{Resource, "resource"},
		{StatTCPRtt, "obi_stat_tcp_rtt_seconds"},
		{StatTCPFailedConnections, "obi_stat_tcp_failed_connections_total"},
		{StatTCPRetransmits, "obi_stat_tcp_retransmits_total"},
		{StatTCPIo, "obi_stat_tcp_io_bytes_total"},
	}

	for _, test := range tests {
		t.Run(string(test.metric.Section), func(t *testing.T) {
			require.NotEmpty(t, test.metric.Prom)
			assert.Equal(t, test.prom, test.metric.Prom)
		})
	}
}

func TestPrometheusNameDerivationFailsFast(t *testing.T) {
	assert.Panics(t, func() {
		metric(Name{Section: "unnameable", OTEL: "..."})
	})
}
