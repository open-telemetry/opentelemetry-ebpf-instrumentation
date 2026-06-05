// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"encoding"
	"fmt"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/obi"
)

// RuntimeToV2 converts an already-loaded v1 runtime configuration into the
// internal config v2 document shape.
func RuntimeToV2(cfg *obi.Config) (*schema.Document, *schema.Extension) {
	if cfg == nil {
		defaultConfig := obi.DefaultConfig
		cfg = &defaultConfig
	}

	ext := &schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Policy:          capturePolicy(cfg),
			Instrumentation: captureInstrumentation(cfg),
			Runtimes:        captureRuntimes(cfg),
			Network:         captureNetwork(cfg),
			Limits:          captureLimits(cfg),
			Engine:          captureEngine(cfg),
			Safety:          captureSafety(cfg),
			Channels:        captureChannels(cfg),
			Rules:           []schema.Rule{},
			Telemetry:       map[string]any{},
		},
		Daemon: daemon(cfg),
	}

	doc := &schema.Document{
		FileFormat:     "1.0",
		Resource:       map[string]any{},
		Propagator:     map[string]any{},
		TracerProvider: map[string]any{},
		MeterProvider:  map[string]any{},
		Extensions:     schema.Extensions{OBI: ext},
	}

	return doc, ext
}

func capturePolicy(cfg *obi.Config) map[string]any {
	return map[string]any{
		"default_action":  "include",
		"match_order":     "first_match_wins",
		"poll_interval":   cfg.Discovery.PollInterval.String(),
		"min_process_age": cfg.Discovery.MinProcessAge.String(),
	}
}

func captureInstrumentation(cfg *obi.Config) map[string]any {
	tracesInstrumentations := cfg.Traces.Instrumentations
	metricsInstrs := metricsInstrumentations(cfg)
	appMetricsEnabled := cfg.Metrics.Features.AnyAppO11yMetric()

	instrumentation := make(map[string]any, len(protocolMappings))
	for _, mapping := range protocolMappings {
		instrumentation[mapping.name] = map[string]any{
			"enabled": protocolEnabled(tracesInstrumentations, metricsInstrs, appMetricsEnabled, mapping),
		}
	}

	http := instrumentation["http"].(map[string]any)
	http["track_request_headers"] = cfg.EBPF.TrackRequestHeaders
	http["request_timeout"] = cfg.EBPF.HTTPRequestTimeout.String()
	http["buffer_size"] = cfg.EBPF.BufferSizes.HTTP

	sql := instrumentation["sql"].(map[string]any)
	sql["heuristic_detect"] = cfg.EBPF.HeuristicSQLDetect
	sql["mysql"] = map[string]any{
		"buffer_size":                    cfg.EBPF.BufferSizes.MySQL,
		"prepared_statements_cache_size": cfg.EBPF.MySQLPreparedStatementsCacheSize,
	}
	sql["postgres"] = map[string]any{
		"buffer_size":                    cfg.EBPF.BufferSizes.Postgres,
		"prepared_statements_cache_size": cfg.EBPF.PostgresPreparedStatementsCacheSize,
	}

	redis := instrumentation["redis"].(map[string]any)
	redis["db_cache"] = map[string]any{
		"enabled":  cfg.EBPF.RedisDBCache.Enabled,
		"max_size": cfg.EBPF.RedisDBCache.MaxSize,
	}

	kafka := instrumentation["kafka"].(map[string]any)
	kafka["buffer_size"] = cfg.EBPF.BufferSizes.Kafka
	kafka["topic_uuid_cache_size"] = cfg.EBPF.KafkaTopicUUIDCacheSize

	mongo := instrumentation["mongo"].(map[string]any)
	mongo["requests_cache_size"] = cfg.EBPF.MongoRequestsCacheSize

	couchbase := instrumentation["couchbase"].(map[string]any)
	couchbase["db_cache_size"] = cfg.EBPF.CouchbaseDBCacheSize

	dns := instrumentation["dns"].(map[string]any)
	dns["request_timeout"] = cfg.EBPF.DNSRequestTimeout.String()

	gpu := instrumentation["gpu"].(map[string]any)
	gpu["enabled_mode"] = textValue(cfg.EBPF.InstrumentCuda)

	return instrumentation
}

func metricsInstrumentations(cfg *obi.Config) []instrumentations.Instrumentation {
	var combined []instrumentations.Instrumentation
	if cfg.OTELMetrics.EndpointEnabled() {
		combined = appendMetricInstrumentations(combined, cfg.OTELMetrics.Instrumentations)
	}
	if cfg.Prometheus.EndpointEnabled() {
		combined = appendMetricInstrumentations(combined, cfg.Prometheus.Instrumentations)
	}
	if len(combined) != 0 {
		return combined
	}

	combined = appendMetricInstrumentations(combined, cfg.OTELMetrics.Instrumentations)
	return appendMetricInstrumentations(combined, cfg.Prometheus.Instrumentations)
}

func appendMetricInstrumentations(
	dst []instrumentations.Instrumentation,
	src []instrumentations.Instrumentation,
) []instrumentations.Instrumentation {
	for _, instr := range src {
		if !containsInstrumentation(dst, instr) {
			dst = append(dst, instr)
		}
	}
	return dst
}

func containsInstrumentation(list []instrumentations.Instrumentation, needle instrumentations.Instrumentation) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func protocolEnabled(
	tracesInstrumentations []instrumentations.Instrumentation,
	metricsInstrumentations []instrumentations.Instrumentation,
	appMetricsEnabled bool,
	mapping protocolMapping,
) map[string]any {
	metricsEnabled := protocolSelected(metricsInstrumentations, mapping, mapping.metricWildcard)
	if mapping.appMetrics {
		metricsEnabled = metricsEnabled && appMetricsEnabled
	}

	return map[string]any{
		"traces":  protocolSelected(tracesInstrumentations, mapping, true),
		"metrics": metricsEnabled,
	}
}

func protocolSelected(list []instrumentations.Instrumentation, mapping protocolMapping, wildcard bool) bool {
	for _, instr := range list {
		if instr == mapping.instr {
			return true
		}
		if instr == instrumentations.InstrumentationALL && wildcard {
			return true
		}
	}
	return false
}

func captureRuntimes(cfg *obi.Config) map[string]any {
	return map[string]any{
		"go": map[string]any{
			"enabled": !cfg.Discovery.SkipGoSpecificTracers,
			"filter":  map[string]any{},
		},
		"nodejs": map[string]any{
			"enabled": cfg.NodeJS.Enabled,
			"filter":  map[string]any{},
		},
		"java": map[string]any{
			"enabled": cfg.Java.Enabled,
			"filter":  map[string]any{},
			"debug": map[string]any{
				"enabled":                  cfg.Java.Debug,
				"bytecode_instrumentation": cfg.Java.DebugInstrumentation,
			},
			"attach_timeout": cfg.Java.Timeout.String(),
		},
	}
}

func captureNetwork(cfg *obi.Config) map[string]any {
	return map[string]any{
		"capture": map[string]any{
			"enabled":     cfg.NetworkFlows.Enable || cfg.Metrics.Features.AnyNetwork(),
			"source":      cfg.NetworkFlows.Source,
			"buffer_size": cfg.EBPF.BufferSizes.TCP,
			"endpoint_identity": map[string]any{
				"agent_ip":           cfg.NetworkFlows.AgentIP,
				"agent_ip_interface": cfg.NetworkFlows.AgentIPIface,
				"agent_ip_family":    cfg.NetworkFlows.AgentIPType,
			},
			"selection": map[string]any{
				"interfaces": map[string]any{
					"include": cfg.NetworkFlows.Interfaces,
					"exclude": cfg.NetworkFlows.ExcludeInterfaces,
				},
				"protocols": map[string]any{
					"include": cfg.NetworkFlows.Protocols,
					"exclude": cfg.NetworkFlows.ExcludeProtocols,
				},
				"direction": cfg.NetworkFlows.Direction,
			},
			"flow_lifecycle": map[string]any{
				"max_tracked_flows": cfg.NetworkFlows.CacheMaxFlows,
				"active_timeout":    cfg.NetworkFlows.CacheActiveTimeout.String(),
				"deduplication": map[string]any{
					"strategy":       cfg.NetworkFlows.Deduper,
					"first_come_ttl": cfg.NetworkFlows.DeduperFCTTL.String(),
				},
				"sampling": cfg.NetworkFlows.Sampling,
			},
			"interface_discovery": map[string]any{
				"mode":          cfg.NetworkFlows.ListenInterfaces,
				"poll_interval": cfg.NetworkFlows.ListenPollPeriod.String(),
			},
			"diagnostics": map[string]any{
				"print_flows": cfg.NetworkFlows.Print,
			},
		},
	}
}

func captureLimits(cfg *obi.Config) map[string]any {
	return map[string]any{
		"network_packets":   cfg.NetworkFlows.CacheMaxFlows,
		"metric_span_names": cfg.Attributes.MetricSpanNameAggregationLimit,
	}
}

func captureEngine(cfg *obi.Config) map[string]any {
	return map[string]any{
		"debug": map[string]any{
			"bpf":            cfg.EBPF.BpfDebug,
			"protocol_print": cfg.EBPF.ProtocolDebug,
		},
		"pid_filter": map[string]any{
			"disabled": cfg.Discovery.BPFPidFilterOff,
		},
		"batching": map[string]any{
			"wakeup_len":    cfg.EBPF.WakeupLen,
			"batch_length":  cfg.EBPF.BatchLength,
			"batch_timeout": cfg.EBPF.BatchTimeout.String(),
		},
		"propagation": map[string]any{
			"context_propagation":      textValue(cfg.EBPF.ContextPropagation),
			"override_bpfloop_enabled": cfg.EBPF.OverrideBPFLoopEnabled,
			"disable_black_box_cp":     cfg.EBPF.DisableBlackBoxCP,
		},
		"traffic": map[string]any{
			"control_backend":     textValue(cfg.EBPF.TCBackend),
			"high_request_volume": cfg.EBPF.HighRequestVolume,
		},
		"transactions": map[string]any{
			"max_duration": cfg.EBPF.MaxTransactionTime.String(),
		},
		"bpf_filesystem": map[string]any{
			"path": cfg.EBPF.BPFFSPath,
		},
	}
}

func captureSafety(cfg *obi.Config) map[string]any {
	return map[string]any{
		"enforce_system_capabilities": cfg.EnforceSysCaps,
	}
}

func captureChannels(cfg *obi.Config) map[string]any {
	return map[string]any{
		"buffer_len":            cfg.ChannelBufferLen,
		"send_timeout":          cfg.ChannelSendTimeout.String(),
		"panic_on_send_timeout": cfg.ChannelSendTimeoutPanic,
	}
}

func daemon(cfg *obi.Config) map[string]any {
	return map[string]any{
		"logging": map[string]any{
			"level":              cfg.LogLevel,
			"format":             cfg.LogConfig,
			"debug_trace_output": cfg.TracePrinter,
		},
		"profiling": map[string]any{
			"port": cfg.ProfilePort,
		},
		"shutdown": map[string]any{
			"timeout": cfg.ShutdownTimeout.String(),
		},
		"internal_metrics": map[string]any{
			"exporter": cfg.InternalMetrics.Exporter,
			"prometheus": map[string]any{
				"port": cfg.InternalMetrics.Prometheus.Port,
				"path": cfg.InternalMetrics.Prometheus.Path,
			},
			"bpf": map[string]any{
				"scrape_interval": cfg.InternalMetrics.BpfMetricScrapeInterval.String(),
			},
		},
	}
}

func textValue(v encoding.TextMarshaler) any {
	raw, err := v.MarshalText()
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}
