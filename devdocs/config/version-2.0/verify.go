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

	rulesValue, ok := get(ex, "obi", "selection", "rules")
	if !ok {
		return errors.New("missing example key [obi selection rules]")
	}
	rules, ok := rulesValue.([]any)
	if !ok {
		return errors.New("example obi.selection.rules is not a list")
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

	rulesValue, ok := get(ex, "obi", "selection", "rules")
	if !ok {
		return errors.New("missing example key [obi selection rules]")
	}
	rules, ok := rulesValue.([]any)
	if !ok {
		return errors.New("example obi.selection.rules is not a list")
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

	tracesEnabled, ok := get(ex, "obi", "instrumentation", "go", "enabled", "traces")
	if !ok {
		return errors.New("missing example key [obi instrumentation go enabled traces]")
	}
	metricsEnabled, ok := get(ex, "obi", "instrumentation", "go", "enabled", "metrics")
	if !ok {
		return errors.New("missing example key [obi instrumentation go enabled metrics]")
	}
	enableTraces := fmt.Sprintf("%v", tracesEnabled) == "true"
	enableMetrics := fmt.Sprintf("%v", metricsEnabled) == "true"
	wantEnabled := !currentSkip
	if enableTraces != wantEnabled || enableMetrics != wantEnabled {
		return fmt.Errorf("mismatch discovery.skip_go_specific_tracers=%v vs obi.instrumentation.go.enabled={traces:%v metrics:%v}", currentSkip, enableTraces, enableMetrics)
	}

	return nil
}

func mustMapApplicationFiltersPerInstrumentation(cur map[string]any, ex map[string]any) error {
	currentValue, ok := get(cur, "filter", "application")
	if !ok {
		return errors.New("missing current key [filter application]")
	}

	protocols := []string{"http", "grpc", "sql", "redis", "kafka", "mongo", "couchbase", "dns", "gpu", "java", "nodejs", "go"}
	signals := []string{"traces", "metrics"}

	for _, protocol := range protocols {
		for _, signal := range signals {
			exampleValue, ok := get(ex, "obi", "instrumentation", protocol, "filters", signal)
			if !ok {
				return fmt.Errorf("missing example key [obi instrumentation %s filters %s]", protocol, signal)
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
		exampleValue, ok := get(ex, "obi", "network", "capture", "filters", signal)
		if !ok {
			return fmt.Errorf("missing example key [obi network capture filters %s]", signal)
		}
		if fmt.Sprintf("%v", currentValue) != fmt.Sprintf("%v", exampleValue) {
			return fmt.Errorf("filter.network mismatch for signal %s", signal)
		}
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
		{[]string{"ebpf", "batch_length"}, []string{"obi", "operations", "capture", "batching", "batch_length"}},
		{[]string{"ebpf", "batch_timeout"}, []string{"obi", "operations", "capture", "batching", "batch_timeout"}},
		{[]string{"ebpf", "wakeup_len"}, []string{"obi", "operations", "capture", "batching", "wakeup_len"}},
		{[]string{"ebpf", "traffic_control_backend"}, []string{"obi", "operations", "capture", "traffic", "control_backend"}},
		{[]string{"ebpf", "bpf_fs_path"}, []string{"obi", "operations", "capture", "bpf_filesystem", "path"}},
		{[]string{"ebpf", "max_transaction_time"}, []string{"obi", "operations", "capture", "transactions", "max_duration"}},
		{[]string{"discovery", "bpf_pid_filter_off"}, []string{"obi", "operations", "capture", "pid_filter", "disabled"}},
		{[]string{"ebpf", "dns_request_timeout"}, []string{"obi", "instrumentation", "dns", "request_timeout"}},
		{[]string{"ebpf", "payload_extraction", "http", "graphql", "enabled"}, []string{"obi", "instrumentation", "http", "payload_extraction", "graphql", "enabled"}},
		{[]string{"ebpf", "payload_extraction", "http", "sqlpp", "enabled"}, []string{"obi", "instrumentation", "http", "payload_extraction", "sqlpp", "enabled"}},
		{[]string{"ebpf", "log_enricher", "cache_ttl"}, []string{"obi", "instrumentation", "http", "log_enrichment", "cache", "ttl"}},
		{[]string{"ebpf", "log_enricher", "cache_size"}, []string{"obi", "instrumentation", "http", "log_enrichment", "cache", "size"}},
		{[]string{"ebpf", "log_enricher", "async_writer_workers"}, []string{"obi", "instrumentation", "http", "log_enrichment", "async_writer", "workers"}},
		{[]string{"ebpf", "log_enricher", "async_writer_channel_len"}, []string{"obi", "instrumentation", "http", "log_enrichment", "async_writer", "channel_len"}},
		{[]string{"ebpf", "buffer_sizes", "http"}, []string{"obi", "instrumentation", "http", "buffer_size"}},
		{[]string{"ebpf", "heuristic_sql_detect"}, []string{"obi", "instrumentation", "sql", "heuristic_detect"}},
		{[]string{"ebpf", "buffer_sizes", "mysql"}, []string{"obi", "instrumentation", "sql", "mysql", "buffer_size"}},
		{[]string{"ebpf", "mysql_prepared_statements_cache_size"}, []string{"obi", "instrumentation", "sql", "mysql", "prepared_statements_cache_size"}},
		{[]string{"ebpf", "buffer_sizes", "postgres"}, []string{"obi", "instrumentation", "sql", "postgres", "buffer_size"}},
		{[]string{"ebpf", "postgres_prepared_statements_cache_size"}, []string{"obi", "instrumentation", "sql", "postgres", "prepared_statements_cache_size"}},
		{[]string{"ebpf", "redis_db_cache", "enabled"}, []string{"obi", "instrumentation", "redis", "db_cache", "enabled"}},
		{[]string{"ebpf", "buffer_sizes", "kafka"}, []string{"obi", "instrumentation", "kafka", "buffer_size"}},

		{[]string{"network", "enable"}, []string{"obi", "network", "capture", "enabled"}},
		{[]string{"network", "source"}, []string{"obi", "network", "capture", "source"}},
		{[]string{"network", "agent_ip"}, []string{"obi", "network", "capture", "endpoint_identity", "agent_ip"}},
		{[]string{"network", "agent_ip_iface"}, []string{"obi", "network", "capture", "endpoint_identity", "agent_ip_interface"}},
		{[]string{"network", "agent_ip_type"}, []string{"obi", "network", "capture", "endpoint_identity", "agent_ip_family"}},
		{[]string{"network", "cache_max_flows"}, []string{"obi", "network", "capture", "flow_lifecycle", "max_tracked_flows"}},
		{[]string{"network", "cache_active_timeout"}, []string{"obi", "network", "capture", "flow_lifecycle", "active_timeout"}},
		{[]string{"network", "deduper"}, []string{"obi", "network", "capture", "flow_lifecycle", "deduplication", "strategy"}},
		{[]string{"network", "deduper_fc_ttl"}, []string{"obi", "network", "capture", "flow_lifecycle", "deduplication", "first_come_ttl"}},
		{[]string{"network", "sampling"}, []string{"obi", "network", "capture", "flow_lifecycle", "sampling"}},
		{[]string{"network", "direction"}, []string{"obi", "network", "capture", "selection", "direction"}},
		{[]string{"network", "listen_interfaces"}, []string{"obi", "network", "capture", "interface_discovery", "mode"}},
		{[]string{"network", "listen_poll_period"}, []string{"obi", "network", "capture", "interface_discovery", "poll_interval"}},
		{[]string{"network", "geo_ip", "cache_expiry"}, []string{"obi", "network", "capture", "enrichment", "geo_ip", "cache", "ttl"}},
		{[]string{"network", "reverse_dns", "cache_expiry"}, []string{"obi", "network", "capture", "enrichment", "reverse_dns", "cache", "ttl"}},
		{[]string{"network", "print_flows"}, []string{"obi", "network", "capture", "diagnostics", "print_flows"}},
		{[]string{"discovery", "min_process_age"}, []string{"obi", "selection", "policy", "min_process_age"}},
		{[]string{"discovery", "route_harvester_timeout"}, []string{"obi", "instrumentation", "http", "routes", "discovery", "timeout"}},
		{[]string{"discovery", "disabled_route_harvesters"}, []string{"obi", "instrumentation", "http", "routes", "discovery", "disabled_languages"}},
		{[]string{"discovery", "route_harvester_advanced", "java_harvest_delay"}, []string{"obi", "instrumentation", "http", "routes", "discovery", "java", "delay"}},

		{[]string{"name_resolver", "cache_len"}, []string{"obi", "enrich", "service_name", "cache", "size"}},
		{[]string{"name_resolver", "cache_expiry"}, []string{"obi", "enrich", "service_name", "cache", "ttl"}},

		{[]string{"attributes", "metric_span_names_limit"}, []string{"obi", "operations", "limits", "metric_span_names"}},
		{[]string{"attributes", "rename_unresolved_hosts"}, []string{"obi", "enrich", "service_name", "unresolved_hosts", "names", "default"}},
		{[]string{"attributes", "kubernetes", "informers_sync_timeout"}, []string{"obi", "enrich", "enrichers", "kubernetes", "informers", "initial_sync_timeout"}},
		{[]string{"attributes", "kubernetes", "informers_resync_period"}, []string{"obi", "enrich", "enrichers", "kubernetes", "informers", "resync_period"}},

		{[]string{"routes", "unmatched"}, []string{"obi", "instrumentation", "http", "routes", "unmatched"}},
		{[]string{"routes", "wildcard_char"}, []string{"obi", "instrumentation", "http", "routes", "wildcard_char"}},
		{[]string{"routes", "max_path_segment_cardinality"}, []string{"obi", "instrumentation", "http", "routes", "max_path_segment_cardinality"}},

		{[]string{"otel_metrics_export", "histogram_aggregation"}, []string{"meter_provider", "readers", "0", "periodic", "exporter", "otlp_grpc", "default_histogram_aggregation"}},
		{[]string{"otel_metrics_export", "reporters_cache_len"}, []string{"obi", "operations", "telemetry", "metrics", "reporters_cache_len"}},
		{[]string{"otel_metrics_export", "ttl"}, []string{"obi", "operations", "telemetry", "metrics", "ttl"}},
		{[]string{"otel_metrics_export", "extra_span_resource_attributes"}, []string{"obi", "operations", "telemetry", "metrics", "prometheus", "extra_span_resource_attributes"}},

		{[]string{"otel_traces_export", "max_queue_size"}, []string{"tracer_provider", "processors", "0", "batch", "max_queue_size"}},
		{[]string{"otel_traces_export", "reporters_cache_len"}, []string{"obi", "operations", "telemetry", "traces", "reporters_cache_len"}},

		{[]string{"prometheus_export", "port"}, []string{"meter_provider", "readers", "1", "pull", "exporter", "prometheus/development", "port"}},
		{[]string{"prometheus_export", "service_cache_size"}, []string{"obi", "operations", "telemetry", "metrics", "prometheus", "span_metrics_service_cache_size"}},
		{[]string{"prometheus_export", "allow_service_graph_self_references"}, []string{"obi", "operations", "telemetry", "metrics", "prometheus", "allow_service_graph_self_references"}},
		{[]string{"prometheus_export", "extra_resource_attributes"}, []string{"obi", "operations", "telemetry", "metrics", "prometheus", "extra_resource_attributes"}},
		{[]string{"prometheus_export", "extra_span_resource_attributes"}, []string{"obi", "operations", "telemetry", "metrics", "prometheus", "extra_span_resource_attributes"}},

		{[]string{"log_level"}, []string{"obi", "operations", "logging", "level"}},
		{[]string{"trace_printer"}, []string{"obi", "operations", "logging", "debug_trace_output"}},
		{[]string{"shutdown_timeout"}, []string{"obi", "operations", "shutdown", "timeout"}},
		{[]string{"profile_port"}, []string{"obi", "operations", "profiling", "port"}},
		{[]string{"enforce_sys_caps"}, []string{"obi", "operations", "safety", "enforce_system_capabilities"}},
		{[]string{"channel_buffer_len"}, []string{"obi", "operations", "runtime", "channels", "buffer_len"}},
		{[]string{"channel_send_timeout"}, []string{"obi", "operations", "runtime", "channels", "send_timeout"}},
		{[]string{"channel_send_timeout_panic"}, []string{"obi", "operations", "runtime", "channels", "panic_on_send_timeout"}},
		{[]string{"internal_metrics", "exporter"}, []string{"obi", "operations", "internal_metrics", "exporter"}},
		{[]string{"internal_metrics", "prometheus", "path"}, []string{"obi", "operations", "internal_metrics", "prometheus", "path"}},
		{[]string{"internal_metrics", "bpf_metric_scrape_interval"}, []string{"obi", "operations", "internal_metrics", "bpf", "scrape_interval"}},

		{[]string{"nodejs", "enabled"}, []string{"obi", "instrumentation", "nodejs", "enabled", "traces"}},
		{[]string{"nodejs", "enabled"}, []string{"obi", "instrumentation", "nodejs", "enabled", "metrics"}},
		{[]string{"javaagent", "enabled"}, []string{"obi", "instrumentation", "java", "enabled", "traces"}},
		{[]string{"javaagent", "enabled"}, []string{"obi", "instrumentation", "java", "enabled", "metrics"}},
		{[]string{"javaagent", "debug"}, []string{"obi", "instrumentation", "java", "debug", "enabled"}},
		{[]string{"javaagent", "debug_instrumentation"}, []string{"obi", "instrumentation", "java", "debug", "bytecode_instrumentation"}},
		{[]string{"javaagent", "attach_timeout"}, []string{"obi", "instrumentation", "java", "attach_timeout"}},
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

	fmt.Printf("feature parity verification passed: %d mapped default checks\n", len(checks)+6)
}
