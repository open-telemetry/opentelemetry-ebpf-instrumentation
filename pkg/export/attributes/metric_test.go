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
		{MCPClientOperationDuration, "mcp_client_operation_duration_seconds"},
		{MCPServerOperationDuration, "mcp_server_operation_duration_seconds"},
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
		{DotnetGCCollections, "dotnet_gc_collections_total"},
		{DotnetProcessMemoryWorkingSet, "dotnet_process_memory_working_set_bytes"},
		{DotnetGCCommittedMemory, "dotnet_gc_last_collection_memory_committed_size_bytes"},
		{DotnetThreadPoolThreadCount, "dotnet_thread_pool_thread_count"},
		{DotnetThreadPoolQueueLength, "dotnet_thread_pool_queue_length"},
		{DotnetTimerCount, "dotnet_timer_count"},
		{DotnetAssemblyCount, "dotnet_assembly_count"},
		{JVMMemoryUsed, "jvm_memory_used_bytes"},
		{JVMMemoryCommitted, "jvm_memory_committed_bytes"},
		{JVMMemoryLimit, "jvm_memory_limit_bytes"},
		{JVMMemoryUsedAfterLastGC, "jvm_memory_used_after_last_gc_bytes"},
		{JVMClassLoaded, "jvm_class_loaded_total"},
		{JVMClassUnloaded, "jvm_class_unloaded_total"},
		{JVMClassCount, "jvm_class_count"},
		{JVMThreadCount, "jvm_thread_count"},
		{JVMCPUTime, "jvm_cpu_time_seconds_total"},
		{JVMCPUCount, "jvm_cpu_count"},
		{JVMCPURecentUtilization, "jvm_cpu_recent_utilization_ratio"},
		{Resource, "resource"},
		{StatTCPRtt, "obi_stat_tcp_rtt_seconds"},
		{StatTCPFailedConnections, "obi_stat_tcp_failed_connections_total"},
		{StatTCPSuccessfulConnections, "obi_stat_tcp_successful_connections_total"},
		{StatTCPRetransmits, "obi_stat_tcp_retransmits_total"},
		{StatTCPIo, "obi_stat_tcp_io_bytes_total"},
		{V8JSGCDuration, "v8js_gc_duration_seconds"},
		{V8JSMemoryHeapLimit, "v8js_memory_heap_limit_bytes"},
		{V8JSMemoryHeapUsed, "v8js_memory_heap_used_bytes"},
		{V8JSMemoryHeapSpaceAvailableSize, "v8js_memory_heap_space_available_size_bytes"},
		{V8JSMemoryHeapSpacePhysicalSize, "v8js_memory_heap_space_physical_size_bytes"},
		// the {resource} annotation unit adds no suffix
		{V8JSResourceActive, "v8js_resource_active"},
	}

	// Span metrics, service graph metrics and the info metrics carry no Section, so they are
	// keyed by their OTEL name below. Every expectation is the name OBI's Prometheus exporter
	// published before these metrics were declared: the consolidation renames nothing.
	tests = append(tests, []struct {
		metric Name
		prom   string
	}{
		// Grafana-convention names, matched literally by Tempo: the absent unit is what keeps
		// the derivation from appending _seconds.
		{SpanMetricsLatencyLegacy, "traces_spanmetrics_latency"},
		{SpanMetricsCallsLegacy, "traces_spanmetrics_calls_total"},
		{SpanMetricsRequestSize, "traces_spanmetrics_size_total"},
		{SpanMetricsResponseSize, "traces_spanmetrics_response_size_total"},
		{SpanMetricsDurationOTel, "traces_span_metrics_duration_seconds"},
		{SpanMetricsCallsOTel, "traces_span_metrics_calls_total"},
		// The servicegraph connector emits these underscore-shaped names itself.
		{ServiceGraphClient, "traces_service_graph_request_client_seconds"},
		{ServiceGraphServer, "traces_service_graph_request_server_seconds"},
		{ServiceGraphFailed, "traces_service_graph_request_failed_total"},
		{ServiceGraphTotal, "traces_service_graph_request_total"},
		{TargetInfo, "target_info"},
		{TracesTargetInfo, "traces_target_info"},
	}...)

	for _, test := range tests {
		name := string(test.metric.Section)
		if name == "" {
			name = test.metric.OTEL
		}
		t.Run(name, func(t *testing.T) {
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
