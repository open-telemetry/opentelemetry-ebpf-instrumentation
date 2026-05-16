// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func asMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func get(root map[string]any, path ...string) (any, bool) {
	cur := any(root)
	for i, p := range path {
		if arr, ok := cur.([]any); ok {
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
			continue
		}

		m := asMap(cur)
		if m == nil {
			return nil, false
		}
		if i == 0 && p == "obi" {
			if _, ok := m["obi"]; !ok {
				extensionsAny, ok := m["extensions"]
				if ok {
					extensionsMap := asMap(extensionsAny)
					if extensionsMap != nil {
						if obiAny, ok := extensionsMap["obi"]; ok {
							cur = obiAny
							continue
						}
					}
				}
			}
		}
		n, ok := m[p]
		if !ok {
			return nil, false
		}
		cur = n
	}
	return cur, true
}

func mustEq(cur map[string]any, ex map[string]any, curPath []string, exPath []string) error {
	cv, ok := get(cur, curPath...)
	if !ok {
		return fmt.Errorf("missing current key %v", curPath)
	}
	ev, ok := get(ex, exPath...)
	if !ok {
		return fmt.Errorf("missing example key %v", exPath)
	}

	if fmt.Sprintf("%v", cv) != fmt.Sprintf("%v", ev) {
		return fmt.Errorf("mismatch current %v=%v example %v=%v", curPath, cv, exPath, ev)
	}
	return nil
}

func mustEqDurationToMilliseconds(cur map[string]any, ex map[string]any, curPath []string, exPath []string) error {
	cv, ok := get(cur, curPath...)
	if !ok {
		return fmt.Errorf("missing current key %v", curPath)
	}
	ev, ok := get(ex, exPath...)
	if !ok {
		return fmt.Errorf("missing example key %v", exPath)
	}

	curDuration, err := time.ParseDuration(fmt.Sprintf("%v", cv))
	if err != nil {
		return fmt.Errorf("invalid current duration %v=%v", curPath, cv)
	}

	var exMillis int64
	switch value := ev.(type) {
	case int:
		exMillis = int64(value)
	case int64:
		exMillis = value
	case float64:
		exMillis = int64(value)
	case string:
		parsed, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return fmt.Errorf("invalid example milliseconds %v=%v", exPath, ev)
		}
		exMillis = parsed
	default:
		return fmt.Errorf("unsupported example milliseconds type for %v=%v", exPath, ev)
	}

	if curDuration.Milliseconds() != exMillis {
		return fmt.Errorf("mismatch current %v=%vms example %v=%v", curPath, curDuration.Milliseconds(), exPath, exMillis)
	}

	return nil
}

func toStringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprintf("%v", item))
	}
	return out
}

func mustMapExcludedSystemPaths(cur map[string]any, ex map[string]any) error {
	currentPathsValue, ok := get(cur, "discovery", "excluded_linux_system_paths")
	if !ok {
		return errors.New("missing current key [discovery excluded_linux_system_paths]")
	}
	currentPaths := toStringSlice(currentPathsValue)
	if len(currentPaths) == 0 {
		return errors.New("current discovery.excluded_linux_system_paths is empty or not a list")
	}

	rulesValue, ok := get(ex, "obi", "capture", "rules")
	if !ok {
		return errors.New("missing example key [obi capture rules]")
	}
	rules, ok := rulesValue.([]any)
	if !ok {
		return errors.New("example obi.capture.rules is not a list")
	}

	foundGlobs := map[string]bool{}
	for _, ruleAny := range rules {
		rule, ok := ruleAny.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprintf("%v", rule["action"]) != "exclude" {
			continue
		}
		match, ok := rule["match"].(map[string]any)
		if !ok {
			continue
		}
		process, ok := match["process"].(map[string]any)
		if !ok {
			continue
		}
		globs := toStringSlice(process["exe_path_glob"])
		for _, g := range globs {
			foundGlobs[g] = true
		}
	}

	for _, p := range currentPaths {
		expectedGlob := strings.TrimSuffix(p, "/") + "/*"
		if !foundGlobs[expectedGlob] {
			return fmt.Errorf("missing scope rule glob for excluded system path: expected %s", expectedGlob)
		}
	}

	return nil
}

func mustMapAlreadyInstrumentedExclusion(cur map[string]any, ex map[string]any) error {
	currentValue, ok := get(cur, "discovery", "exclude_otel_instrumented_services")
	if !ok {
		return errors.New("missing current key [discovery exclude_otel_instrumented_services]")
	}
	wantExclude := fmt.Sprintf("%v", currentValue) == "true"

	defaultPortValue, ok := get(cur, "discovery", "default_otlp_grpc_port")
	if !ok {
		return errors.New("missing current key [discovery default_otlp_grpc_port]")
	}
	wantPort := fmt.Sprintf("%v", defaultPortValue)

	rulesValue, ok := get(ex, "obi", "capture", "rules")
	if !ok {
		return errors.New("missing example key [obi capture rules]")
	}
	rules, ok := rulesValue.([]any)
	if !ok {
		return errors.New("example obi.capture.rules is not a list")
	}

	found := false
	for _, ruleAny := range rules {
		rule, ok := ruleAny.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprintf("%v", rule["action"]) != "exclude" {
			continue
		}
		match, ok := rule["match"].(map[string]any)
		if !ok {
			continue
		}
		process, ok := match["process"].(map[string]any)
		if !ok {
			continue
		}
		exportsOTLP, ok := process["exports_otlp"].(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprintf("%v", exportsOTLP["port"]) != wantPort {
			return fmt.Errorf("mismatch discovery.default_otlp_grpc_port=%s vs process.exports_otlp.port=%v", wantPort, exportsOTLP["port"])
		}
		if fmt.Sprintf("%v", exportsOTLP["protocol"]) == "" {
			return errors.New("missing process.exports_otlp.protocol in already-instrumented exclusion rule")
		}
		found = true
		break
	}

	if wantExclude && !found {
		return errors.New("missing selection rule for already-instrumented exclusion")
	}
	if !wantExclude && found {
		return errors.New("unexpected already-instrumented exclusion rule while source default is false")
	}

	return nil
}

func mustMapGoSpecificTracers(cur map[string]any, ex map[string]any) error {
	currentValue, ok := get(cur, "discovery", "skip_go_specific_tracers")
	if !ok {
		return errors.New("missing current key [discovery skip_go_specific_tracers]")
	}
	currentSkip := fmt.Sprintf("%v", currentValue) == "true"

	goEnabled, ok := get(ex, "obi", "capture", "runtimes", "go", "enabled")
	if !ok {
		return errors.New("missing example key [obi runtimes go enabled]")
	}
	enableGo := fmt.Sprintf("%v", goEnabled) == "true"
	wantEnabled := !currentSkip
	if enableGo != wantEnabled {
		return fmt.Errorf("mismatch discovery.skip_go_specific_tracers=%v vs obi.runtimes.go.enabled=%v", currentSkip, enableGo)
	}

	return nil
}

func mustMapApplicationFiltersPerInstrumentation(cur map[string]any, ex map[string]any) error {
	currentValue, ok := get(cur, "filter", "application")
	if !ok {
		return errors.New("missing current key [filter application]")
	}

	protocols := []string{"http", "grpc", "sql", "redis", "kafka", "mongo", "couchbase", "dns", "gpu"}
	signals := []string{"traces", "metrics"}

	for _, protocol := range protocols {
		for _, signal := range signals {
			exampleValue, ok := get(ex, "obi", "capture", "instrumentation", protocol, "filters", signal)
			if !ok {
				return fmt.Errorf("missing example key [obi capture instrumentation %s filters %s]", protocol, signal)
			}
			if fmt.Sprintf("%v", currentValue) != fmt.Sprintf("%v", exampleValue) {
				return fmt.Errorf("filter.application mismatch for protocol %s signal %s", protocol, signal)
			}
		}
	}

	return nil
}

func mustMapNetworkFiltersPerSignal(cur map[string]any, ex map[string]any) error {
	currentValue, ok := get(cur, "filter", "network")
	if !ok {
		return errors.New("missing current key [filter network]")
	}

	signals := []string{"traces", "metrics"}
	for _, signal := range signals {
		exampleValue, ok := get(ex, "obi", "capture", "network", "capture", "filters", signal)
		if !ok {
			return fmt.Errorf("missing example key [obi capture network capture filters %s]", signal)
		}
		if fmt.Sprintf("%v", currentValue) != fmt.Sprintf("%v", exampleValue) {
			return fmt.Errorf("filter.network mismatch for signal %s", signal)
		}
	}

	return nil
}

func mustMapPayloadExtractionMembership(cur map[string]any, ex map[string]any, extractor string) error {
	currentValue, ok := get(cur, "ebpf", "payload_extraction", "http", extractor, "enabled")
	if !ok {
		return fmt.Errorf("missing current key [ebpf payload_extraction http %s enabled]", extractor)
	}

	enabledValue, ok := get(ex, "obi", "capture", "instrumentation", "http", "payload_extraction", "enabled")
	if !ok {
		return errors.New("missing example key [obi capture instrumentation http payload_extraction enabled]")
	}
	enabledValues := toStringSlice(enabledValue)

	wantEnabled := fmt.Sprintf("%v", currentValue) == "true"
	found := false
	for _, item := range enabledValues {
		if item == extractor {
			found = true
			break
		}
	}

	if found != wantEnabled {
		return fmt.Errorf("payload extraction mismatch for %s: current=%v example list=%v", extractor, wantEnabled, enabledValues)
	}

	return nil
}

//go:embed .verify/default-config-current.yaml
var defaultConf []byte

//go:embed examples/default-configuration.yaml
var v2DefaultConf []byte

func main() {
	var cur map[string]any
	var ex map[string]any
	if err := yaml.Unmarshal(defaultConf, &cur); err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(v2DefaultConf, &ex); err != nil {
		panic(err)
	}

	checks := []struct {
		cur []string
		ex  []string
	}{
		{[]string{"ebpf", "batch_length"}, []string{"obi", "capture", "engine", "batching", "batch_length"}},
		{[]string{"ebpf", "batch_timeout"}, []string{"obi", "capture", "engine", "batching", "batch_timeout"}},
		{[]string{"ebpf", "wakeup_len"}, []string{"obi", "capture", "engine", "batching", "wakeup_len"}},
		{[]string{"ebpf", "traffic_control_backend"}, []string{"obi", "capture", "engine", "traffic", "control_backend"}},
		{[]string{"ebpf", "bpf_fs_path"}, []string{"obi", "capture", "engine", "bpf_filesystem", "path"}},
		{[]string{"ebpf", "max_transaction_time"}, []string{"obi", "capture", "engine", "transactions", "max_duration"}},
		{[]string{"discovery", "bpf_pid_filter_off"}, []string{"obi", "capture", "engine", "pid_filter", "disabled"}},
		{[]string{"ebpf", "dns_request_timeout"}, []string{"obi", "capture", "instrumentation", "dns", "request_timeout"}},
		{[]string{"ebpf", "log_enricher", "cache_ttl"}, []string{"obi", "correlation", "log_trace_annotation", "cache", "ttl"}},
		{[]string{"ebpf", "log_enricher", "cache_size"}, []string{"obi", "correlation", "log_trace_annotation", "cache", "size"}},
		{[]string{"ebpf", "log_enricher", "async_writer_workers"}, []string{"obi", "correlation", "log_trace_annotation", "async_writer", "workers"}},
		{[]string{"ebpf", "log_enricher", "async_writer_channel_len"}, []string{"obi", "correlation", "log_trace_annotation", "async_writer", "channel_len"}},
		{[]string{"ebpf", "buffer_sizes", "http"}, []string{"obi", "capture", "instrumentation", "http", "buffer_size"}},
		{[]string{"ebpf", "heuristic_sql_detect"}, []string{"obi", "capture", "instrumentation", "sql", "heuristic_detect"}},
		{[]string{"ebpf", "buffer_sizes", "mysql"}, []string{"obi", "capture", "instrumentation", "sql", "mysql", "buffer_size"}},
		{[]string{"ebpf", "mysql_prepared_statements_cache_size"}, []string{"obi", "capture", "instrumentation", "sql", "mysql", "prepared_statements_cache_size"}},
		{[]string{"ebpf", "buffer_sizes", "postgres"}, []string{"obi", "capture", "instrumentation", "sql", "postgres", "buffer_size"}},
		{[]string{"ebpf", "postgres_prepared_statements_cache_size"}, []string{"obi", "capture", "instrumentation", "sql", "postgres", "prepared_statements_cache_size"}},
		{[]string{"ebpf", "redis_db_cache", "enabled"}, []string{"obi", "capture", "instrumentation", "redis", "db_cache", "enabled"}},
		{[]string{"ebpf", "buffer_sizes", "kafka"}, []string{"obi", "capture", "instrumentation", "kafka", "buffer_size"}},

		{[]string{"network", "enable"}, []string{"obi", "capture", "network", "capture", "enabled"}},
		{[]string{"network", "source"}, []string{"obi", "capture", "network", "capture", "source"}},
		{[]string{"network", "agent_ip"}, []string{"obi", "capture", "network", "capture", "endpoint_identity", "agent_ip"}},
		{[]string{"network", "agent_ip_iface"}, []string{"obi", "capture", "network", "capture", "endpoint_identity", "agent_ip_interface"}},
		{[]string{"network", "agent_ip_type"}, []string{"obi", "capture", "network", "capture", "endpoint_identity", "agent_ip_family"}},
		{[]string{"network", "cache_max_flows"}, []string{"obi", "capture", "network", "capture", "flow_lifecycle", "max_tracked_flows"}},
		{[]string{"network", "cache_active_timeout"}, []string{"obi", "capture", "network", "capture", "flow_lifecycle", "active_timeout"}},
		{[]string{"network", "deduper"}, []string{"obi", "capture", "network", "capture", "flow_lifecycle", "deduplication", "strategy"}},
		{[]string{"network", "deduper_fc_ttl"}, []string{"obi", "capture", "network", "capture", "flow_lifecycle", "deduplication", "first_come_ttl"}},
		{[]string{"network", "sampling"}, []string{"obi", "capture", "network", "capture", "flow_lifecycle", "sampling"}},
		{[]string{"network", "direction"}, []string{"obi", "capture", "network", "capture", "selection", "direction"}},
		{[]string{"network", "listen_interfaces"}, []string{"obi", "capture", "network", "capture", "interface_discovery", "mode"}},
		{[]string{"network", "listen_poll_period"}, []string{"obi", "capture", "network", "capture", "interface_discovery", "poll_interval"}},
		{[]string{"network", "geo_ip", "cache_expiry"}, []string{"obi", "capture", "network", "capture", "enrichment", "geo_ip", "cache", "ttl"}},
		{[]string{"network", "reverse_dns", "cache_expiry"}, []string{"obi", "capture", "network", "capture", "enrichment", "reverse_dns", "cache", "ttl"}},
		{[]string{"network", "print_flows"}, []string{"obi", "capture", "network", "capture", "diagnostics", "print_flows"}},
		{[]string{"discovery", "min_process_age"}, []string{"obi", "capture", "policy", "min_process_age"}},
		{[]string{"discovery", "route_harvester_timeout"}, []string{"obi", "capture", "instrumentation", "http", "routes", "discovery", "timeout"}},
		{[]string{"discovery", "disabled_route_harvesters"}, []string{"obi", "capture", "instrumentation", "http", "routes", "discovery", "disabled_languages"}},
		{[]string{"discovery", "route_harvester_advanced", "java_harvest_delay"}, []string{"obi", "capture", "instrumentation", "http", "routes", "discovery", "java", "delay"}},

		{[]string{"name_resolver", "cache_len"}, []string{"obi", "enrich", "service_name", "cache", "size"}},
		{[]string{"name_resolver", "cache_expiry"}, []string{"obi", "enrich", "service_name", "cache", "ttl"}},

		{[]string{"attributes", "metric_span_names_limit"}, []string{"obi", "capture", "limits", "metric_span_names"}},
		{[]string{"attributes", "rename_unresolved_hosts"}, []string{"obi", "enrich", "service_name", "unresolved_hosts", "names", "default"}},
		{[]string{"attributes", "kubernetes", "informers_sync_timeout"}, []string{"obi", "enrich", "enrichers", "kubernetes", "informers", "initial_sync_timeout"}},
		{[]string{"attributes", "kubernetes", "informers_resync_period"}, []string{"obi", "enrich", "enrichers", "kubernetes", "informers", "resync_period"}},

		{[]string{"routes", "unmatched"}, []string{"obi", "capture", "instrumentation", "http", "routes", "unmatched"}},
		{[]string{"routes", "wildcard_char"}, []string{"obi", "capture", "instrumentation", "http", "routes", "wildcard_char"}},
		{[]string{"routes", "max_path_segment_cardinality"}, []string{"obi", "capture", "instrumentation", "http", "routes", "max_path_segment_cardinality"}},
		{[]string{"ebpf", "payload_extraction", "http", "sqlpp", "endpoint_patterns"}, []string{"obi", "capture", "instrumentation", "http", "payload_extraction", "sqlpp", "endpoint_patterns"}},

		{[]string{"otel_metrics_export", "histogram_aggregation"}, []string{"meter_provider", "readers", "0", "periodic", "exporter", "otlp_grpc", "default_histogram_aggregation"}},
		{[]string{"otel_metrics_export", "reporters_cache_len"}, []string{"obi", "capture", "telemetry", "metrics", "reporters_cache_len"}},
		{[]string{"otel_metrics_export", "ttl"}, []string{"obi", "capture", "telemetry", "metrics", "ttl"}},
		{[]string{"otel_metrics_export", "extra_span_resource_attributes"}, []string{"obi", "daemon", "telemetry", "metrics", "prometheus", "extra_span_resource_attributes"}},

		{[]string{"otel_traces_export", "max_queue_size"}, []string{"tracer_provider", "processors", "0", "batch", "max_queue_size"}},
		{[]string{"otel_traces_export", "reporters_cache_len"}, []string{"obi", "capture", "telemetry", "traces", "reporters_cache_len"}},

		{[]string{"prometheus_export", "port"}, []string{"meter_provider", "readers", "1", "pull", "exporter", "prometheus/development", "port"}},
		{[]string{"prometheus_export", "service_cache_size"}, []string{"obi", "daemon", "telemetry", "metrics", "prometheus", "span_metrics_service_cache_size"}},
		{[]string{"prometheus_export", "allow_service_graph_self_references"}, []string{"obi", "daemon", "telemetry", "metrics", "prometheus", "allow_service_graph_self_references"}},
		{[]string{"prometheus_export", "extra_resource_attributes"}, []string{"obi", "daemon", "telemetry", "metrics", "prometheus", "extra_resource_attributes"}},
		{[]string{"prometheus_export", "extra_span_resource_attributes"}, []string{"obi", "daemon", "telemetry", "metrics", "prometheus", "extra_span_resource_attributes"}},

		{[]string{"log_config"}, []string{"obi", "daemon", "logging", "format"}},
		{[]string{"log_level"}, []string{"obi", "daemon", "logging", "level"}},
		{[]string{"trace_printer"}, []string{"obi", "daemon", "logging", "debug_trace_output"}},
		{[]string{"shutdown_timeout"}, []string{"obi", "daemon", "shutdown", "timeout"}},
		{[]string{"profile_port"}, []string{"obi", "daemon", "profiling", "port"}},
		{[]string{"enforce_sys_caps"}, []string{"obi", "capture", "safety", "enforce_system_capabilities"}},
		{[]string{"channel_buffer_len"}, []string{"obi", "capture", "channels", "buffer_len"}},
		{[]string{"channel_send_timeout"}, []string{"obi", "capture", "channels", "send_timeout"}},
		{[]string{"channel_send_timeout_panic"}, []string{"obi", "capture", "channels", "panic_on_send_timeout"}},
		{[]string{"internal_metrics", "exporter"}, []string{"obi", "daemon", "internal_metrics", "exporter"}},
		{[]string{"internal_metrics", "prometheus", "path"}, []string{"obi", "daemon", "internal_metrics", "prometheus", "path"}},
		{[]string{"internal_metrics", "bpf_metric_scrape_interval"}, []string{"obi", "daemon", "internal_metrics", "bpf", "scrape_interval"}},

		{[]string{"nodejs", "enabled"}, []string{"obi", "capture", "runtimes", "nodejs", "enabled"}},
		{[]string{"javaagent", "enabled"}, []string{"obi", "capture", "runtimes", "java", "enabled"}},
		{[]string{"javaagent", "debug"}, []string{"obi", "capture", "runtimes", "java", "debug", "enabled"}},
		{[]string{"javaagent", "debug_instrumentation"}, []string{"obi", "capture", "runtimes", "java", "debug", "bytecode_instrumentation"}},
		{[]string{"javaagent", "attach_timeout"}, []string{"obi", "capture", "runtimes", "java", "attach_timeout"}},
	}

	failures := 0
	for _, c := range checks {
		if err := mustEq(cur, ex, c.cur, c.ex); err != nil {
			fmt.Println("FAIL:", err)
			failures++
		}
	}

	if err := mustEqDurationToMilliseconds(
		cur,
		ex,
		[]string{"otel_traces_export", "batch_timeout"},
		[]string{"tracer_provider", "processors", "0", "batch", "schedule_delay"},
	); err != nil {
		fmt.Println("FAIL:", err)
		failures++
	}

	if failures > 0 {
		fmt.Printf("verification failed: %d mismatches\n", failures)
		os.Exit(1)
	}

	if err := mustMapExcludedSystemPaths(cur, ex); err != nil {
		fmt.Println("FAIL:", err)
		fmt.Printf("verification failed: %d mismatches\n", failures+1)
		os.Exit(1)
	}

	if err := mustMapAlreadyInstrumentedExclusion(cur, ex); err != nil {
		fmt.Println("FAIL:", err)
		fmt.Printf("verification failed: %d mismatches\n", failures+1)
		os.Exit(1)
	}

	if err := mustMapGoSpecificTracers(cur, ex); err != nil {
		fmt.Println("FAIL:", err)
		fmt.Printf("verification failed: %d mismatches\n", failures+1)
		os.Exit(1)
	}

	if err := mustMapApplicationFiltersPerInstrumentation(cur, ex); err != nil {
		fmt.Println("FAIL:", err)
		fmt.Printf("verification failed: %d mismatches\n", failures+1)
		os.Exit(1)
	}

	if err := mustMapNetworkFiltersPerSignal(cur, ex); err != nil {
		fmt.Println("FAIL:", err)
		fmt.Printf("verification failed: %d mismatches\n", failures+1)
		os.Exit(1)
	}

	for _, extractor := range []string{"graphql", "elasticsearch", "aws", "sqlpp"} {
		if err := mustMapPayloadExtractionMembership(cur, ex, extractor); err != nil {
			fmt.Println("FAIL:", err)
			fmt.Printf("verification failed: %d mismatches\n", failures+1)
			os.Exit(1)
		}
	}

	fmt.Printf("feature parity verification passed: %d mapped default checks\n", len(checks)+10)
}
