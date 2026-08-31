// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/confmap"

	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/health"
	"go.opentelemetry.io/obi/pkg/internal/avoidedsvc"
	"go.opentelemetry.io/obi/pkg/internal/pipe/cidr"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
	"go.opentelemetry.io/obi/pkg/transform"
)

type envMap map[string]string

func TestJoinMetricsConfigIncludesPerServiceFeatures(t *testing.T) {
	cfg := Config{
		Metrics: perapp.GlobalMetricsConfig{
			Features: export.FeatureApplicationRED,
		},
		Discovery: services.DiscoveryConfig{
			Instrument: services.GlobDefinitionCriteria{
				{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
			},
			Services: services.RegexDefinitionCriteria{
				{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureNetwork}},
			},
		},
	}

	joint := cfg.JoinMetricsConfig()

	assert.Equal(t, export.FeatureApplicationRED|export.FeatureApplicationRuntime|export.FeatureNetwork, joint.Features)
}

func TestConfig_Overrides(t *testing.T) {
	userConfig := bytes.NewBufferString(`
log_format: json
trace_printer: json
shutdown_timeout: 30s
channel_buffer_len: 33
channel_send_timeout: 10s
channel_send_timeout_panic: true
ebpf:
  functions:
    - FooBar
otel_metrics_export:
  ttl: 5m
  endpoint: localhost:3030
  buckets:
    duration_histogram: [0, 1, 2]
  histogram_aggregation: base2_exponential_bucket_histogram
  exponential_histogram:
    max_size: 128
    max_scale: 16
prometheus_export:
  ttl: 1s
  buckets:
    request_size_histogram: [0, 10, 20, 22]
    response_size_histogram: [0, 10, 20, 22]
    gen_ai_client_token_usage_histogram: [1, 2, 3, 4]
    gen_ai_client_operation_duration_histogram: [5, 6, 7, 8]
attributes:
  rename_unresolved_hosts: ""
  rename_unresolved_hosts_outgoing: ""
  rename_unresolved_hosts_incoming: ""
  kubernetes:
    kubeconfig_path: /foo/bar
    enable: true
    informers_sync_timeout: 30s
    resource_labels:
      service.namespace: ["huha.com/yeah"]
  instance_id:
    dns: true
  host_id:
    override: the-host-id
    fetch_timeout: 4s
  select:
    obi.network.flow:
      include: ["foo", "bar"]
      exclude: ["baz", "bae"]
    obi.stat.tcp.rtt:
      include: ["src.port", "dst.port"]
      exclude: ["src.door", "dst.door"]
  extra_group_attributes:
    k8s_app_meta: ["k8s.app.version"]	  
network:
  enable: true
  cidrs:
    - 10.244.0.0/16
discovery:
  min_process_age: 5s
`)
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "tras")
	t.Setenv("OTEL_EBPF_NETWORK_AGENT_IP", "1.2.3.4")
	t.Setenv("OTEL_EBPF_OPEN_PORT", "8080-8089")
	t.Setenv("OTEL_SERVICE_NAME", "svc-name")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:3131")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "localhost:3232")
	unsetEnv(t,
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
		"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
	)
	t.Setenv("OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT", "3210")
	t.Setenv("KUBECONFIG", "/foo/bar")
	t.Setenv("OTEL_EBPF_NAME_RESOLVER_SOURCES", "k8s,dns")

	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())

	// first test executable, as we can't test equality on it
	assert.True(t, cfg.Exec.MatchString("atrassss"))
	assert.False(t, cfg.Exec.MatchString("foobar"))

	// test also openports by the same reason
	assert.True(t, cfg.Port.Matches(8088))
	assert.False(t, cfg.Port.Matches(8078))
	assert.False(t, cfg.Port.Matches(8098))

	nc := DefaultNetworkConfig
	nc.Enable = true
	nc.AgentIP = "1.2.3.4"
	nc.CIDRs = cidr.Definitions{{CIDR: "10.244.0.0/16"}}

	sc := DefaultStatsConfig

	metaSources := maps.Clone(kube.DefaultResourceLabels)
	metaSources["service.namespace"] = []string{"huha.com/yeah"}

	assert.Equal(t, &Config{
		Exec:        cfg.Exec,
		Port:        cfg.Port,
		ServiceName: "svc-name",

		ChannelBufferLen:        33,
		ChannelSendTimeout:      10 * time.Second,
		ChannelSendTimeoutPanic: true,

		LogLevel:        LogLevelInfo,
		LogFormat:       LogFormatJSON,
		ShutdownTimeout: 30 * time.Second,
		EnforceSysCaps:  false,
		TracePrinter:    "json",
		EBPF: config.EBPFTracer{
			BatchLength:               100,
			BatchTimeout:              time.Second,
			WakeupLen:                 500,
			StatsWakeupDataBytes:      4096,
			HTTPRequestTimeout:        0,
			GoHTTPClientBufferTimeout: time.Second,
			MaxTransactionTime:        5 * time.Minute,
			TCBackend:                 config.TCBackendAuto,
			DNSRequestTimeout:         5 * time.Second,
			ContextPropagation:        config.ContextPropagationDisabled,
			RedisDBCache: config.RedisDBCacheConfig{
				Enabled: false,
				MaxSize: 1000,
			},
			BufferSizes: config.EBPFBufferSizes{
				HTTP:      0,
				MySQL:     0,
				Postgres:  0,
				Kafka:     0,
				MSSQL:     0,
				TCP:       0,
				Aerospike: 0,
			},
			MySQLPreparedStatementsCacheSize:    1024,
			PostgresPreparedStatementsCacheSize: 1024,
			MSSQLPreparedStatementsCacheSize:    1024,
			MongoRequestsCacheSize:              1024,
			KafkaTopicUUIDCacheSize:             1024,
			CouchbaseDBCacheSize:                1024,
			PayloadExtraction: config.PayloadExtraction{
				HTTP: config.HTTPConfig{
					SQLPP: config.SQLPPConfig{
						EndpointPatterns: []string{
							"/query/service",
						},
					},
					Enrichment: config.EnrichmentConfig{
						Policy: config.HTTPParsingPolicy{
							DefaultAction: config.HTTPParsingDefaultAction{
								Headers: config.HTTPParsingActionExclude,
								Body:    config.HTTPParsingActionExclude,
							},
							DefaultObfuscationString: "***",
						},
						Rules: []config.HTTPParsingRule{},
					},
				},
			},
			LogEnricher: config.LogEnricherConfig{
				FieldNames: config.LogEnricherFieldNames{
					TraceID: "trace_id",
					SpanID:  "span_id",
				},
				PlainText: config.LogEnricherPlainTextConfig{
					Enabled:   true,
					Placement: config.LogEnricherPlacementSuffix,
					Multiline: config.LogEnricherMultilineFirstLine,
				},
				CacheTTL:              30 * time.Minute,
				CacheSize:             128,
				AsyncWriterWorkers:    8,
				AsyncWriterChannelLen: 500,
			},
			BPFFSPath:      "/sys/fs/bpf/",
			InstrumentCuda: config.CudaModeAuto,
		},
		NetworkFlows: nc,
		Stats:        sc,
		Metrics: perapp.GlobalMetricsConfig{
			// after normalization, network feature is added from network > enable: true
			Features: export.FeatureApplicationRED | export.FeatureNetwork,
		},
		OTELMetrics: otelcfg.MetricsConfig{
			OTELIntervalMS:    60_000,
			CommonEndpoint:    "localhost:3131",
			MetricsEndpoint:   "localhost:3030",
			Protocol:          otelcfg.ProtocolUnset,
			ReportersCacheLen: ReporterLRUSize,
			Buckets: export.Buckets{
				DurationHistogram:            []float64{0, 1, 2},
				RequestSizeHistogram:         export.DefaultBuckets.RequestSizeHistogram,
				ResponseSizeHistogram:        export.DefaultBuckets.ResponseSizeHistogram,
				GenAITokenUsageHistogram:     export.DefaultBuckets.GenAITokenUsageHistogram,
				GenAIClientDurationHistogram: export.DefaultBuckets.GenAIClientDurationHistogram,
				StatTCPRttHistogram:          export.DefaultBuckets.StatTCPRttHistogram,
				V8JSGCDurationHistogram:      export.DefaultBuckets.V8JSGCDurationHistogram,
			},
			Instrumentations: []instrumentations.Instrumentation{
				instrumentations.InstrumentationALL,
			},
			HistogramAggregation: "base2_exponential_bucket_histogram",
			ExponentialHistogram: otelcfg.ExponentialHistogramConfig{
				MaxSize:  128,
				MaxScale: 16,
			},
			TTL: 5 * time.Minute,
		},
		Traces: otelcfg.TracesConfig{
			Protocol:          otelcfg.ProtocolUnset,
			CommonEndpoint:    "localhost:3131",
			TracesEndpoint:    "localhost:3232",
			BatchMaxSize:      4096,
			QueueSize:         16384,
			BatchTimeout:      15 * time.Second,
			ReportersCacheLen: ReporterLRUSize,
			Instrumentations: []instrumentations.Instrumentation{
				instrumentations.InstrumentationHTTP,
				instrumentations.InstrumentationGRPC,
				instrumentations.InstrumentationSQL,
				instrumentations.InstrumentationRedis,
				instrumentations.InstrumentationKafka,
				instrumentations.InstrumentationMQTT,
				instrumentations.InstrumentationNATS,
				instrumentations.InstrumentationAMQP,
				instrumentations.InstrumentationMongo,
				instrumentations.InstrumentationCouchbase,
				instrumentations.InstrumentationMemcached,
				instrumentations.InstrumentationSunRPC,
				instrumentations.InstrumentationAerospike,
				// no traces for DNS and GPU by default
			},
		},
		Prometheus: prom.PrometheusConfig{
			Path: "/metrics",
			Instrumentations: []instrumentations.Instrumentation{
				instrumentations.InstrumentationALL,
			},
			TTL:                         time.Second,
			SpanMetricsServiceCacheSize: 10000,
			NativeHistogram:             prom.DefaultNativeHistogramConfig,
			Buckets: export.Buckets{
				DurationHistogram:            export.DefaultBuckets.DurationHistogram,
				RequestSizeHistogram:         []float64{0, 10, 20, 22},
				ResponseSizeHistogram:        []float64{0, 10, 20, 22},
				GenAITokenUsageHistogram:     []float64{1, 2, 3, 4},
				GenAIClientDurationHistogram: []float64{5, 6, 7, 8},
				StatTCPRttHistogram:          export.DefaultBuckets.StatTCPRttHistogram,
				V8JSGCDurationHistogram:      export.DefaultBuckets.V8JSGCDurationHistogram,
			},
		},
		InternalMetrics: imetrics.InternalMetricsConfig{
			Exporter: imetrics.InternalMetricsExporterDisabled,
			AvoidedServices: imetrics.AvoidedServicesConfig{
				Limit: avoidedsvc.DefaultLimit,
			},
			Prometheus: imetrics.PrometheusEndpointConfig{
				Port: 3210,
				Path: "/internal/metrics",
			},
			BpfMetricScrapeInterval: 15 * time.Second,
		},
		Attributes: Attributes{
			InstanceID: config.InstanceIDConfig{
				HostnameDNSResolution: true,
			},
			Kubernetes: transform.KubernetesDecorator{
				KubeconfigPath:           "/foo/bar",
				Enable:                   kubeflags.EnabledTrue,
				InformersSyncTimeout:     30 * time.Second,
				ReconnectInitialInterval: 5 * time.Second,
				InformersResyncPeriod:    30 * time.Minute,
				ResourceLabels:           metaSources,
			},
			HostID: HostIDConfig{
				Override: "the-host-id",
			},
			Select: attributes.Selection{
				attributes.NetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"foo", "bar"},
					Exclude: []string{"baz", "bae"},
				},
				attributes.StatTCPRtt.Section: attributes.InclusionLists{
					Include: []string{"src.port", "dst.port"},
					Exclude: []string{"src.door", "dst.door"},
				},
			},
			ExtraGroupAttributes: map[string][]attr.Name{
				"k8s_app_meta": {"k8s.app.version"},
			},
			MetadataRetry:                  meta.DefaultRetryConfig,
			MetricSpanNameAggregationLimit: 100,
		},
		Routes: &transform.RoutesConfig{
			Unmatch:                   transform.UnmatchHeuristic,
			WildcardChar:              "*",
			MaxPathSegmentCardinality: 10,
		},
		NameResolver: &transform.NameResolverConfig{
			Sources:  []transform.Source{transform.SourceK8s, transform.SourceDNS},
			CacheLen: 1024,
			CacheTTL: 5 * time.Minute,
		},
		Discovery: services.DiscoveryConfig{
			ExcludeOTelInstrumentedServices: true,
			MinProcessAge:                   5 * time.Second,
			ProcessContextPollInterval:      time.Second,
			DefaultExcludeServices: services.RegexDefinitionCriteria{
				services.RegexSelector{
					Path: services.NewRegexp("(?:^|/)(obi$|otelcol[^/]*$)"),
				},
				services.RegexSelector{
					Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &k8sDefaultNamespacesRegex},
				},
			},
			DefaultExcludeInstrument: services.GlobDefinitionCriteria{
				services.GlobAttributes{
					Path: services.NewGlob("{*/obi,obi,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}"),
				},
				services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{"k8s_namespace": &k8sDefaultNamespacesGlob},
				},
			},
			DefaultOtlpGRPCPort:   4317,
			RouteHarvesterTimeout: 10 * time.Second,
			RouteHarvestConfig: services.RouteHarvestingConfig{
				JavaHarvestDelay: 5 * time.Second,
			},
			ExcludedLinuxSystemPaths: []string{"/lib/systemd/", "/usr/lib/systemd/", "/usr/libexec/", "/sbin/", "/usr/sbin/"},
		},
		NodeJS: NodeJSConfig{
			Enabled: true,
		},
		Java: JavaConfig{
			Enabled: true,
			Timeout: 10 * time.Second,
		},
		JVMRuntimeMetrics: JVMRuntimeMetricsConfig{
			SamplingInterval: time.Second,
		},
		HealthCheck: HealthCheckConfig{
			Port:          0,
			ListenAddress: health.DefaultListenAddress,
		},
	}, cfg)
}

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()

	for _, key := range keys {
		if value, exists := os.LookupEnv(key); exists {
			t.Setenv(key, value)
		} else {
			t.Setenv(key, "")
		}
		require.NoError(t, os.Unsetenv(key))
	}
}

func TestConfig_ServiceName(t *testing.T) {
	// ServiceName property can be handled via two different env vars OTEL_EBPF_SERVICE_NAME and OTEL_SERVICE_NAME (for
	// compatibility with OpenTelemetry)
	t.Setenv("OTEL_EBPF_SERVICE_NAME", "some-svc-name")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, "some-svc-name", cfg.ServiceName)
}

// a literal envDefault on a yaml-configurable field is applied by env.Parse
// after the YAML layer, silently overwriting yaml values whenever the env var
// is unset; defaults for such fields belong in DefaultConfig. The ${VAR}
// indirection form is exempt: it expands to nothing when the var is unset.
func TestConfig_NoLiteralEnvDefaultOnYamlFields(t *testing.T) {
	var violations []string
	seen := map[reflect.Type]bool{}
	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			yamlTag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			envDefault := f.Tag.Get("envDefault")
			if yamlTag != "" && yamlTag != "-" && envDefault != "" && !strings.HasPrefix(envDefault, "${") {
				violations = append(violations, path+"."+f.Name)
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	walk(reflect.TypeFor[Config](), "Config")
	assert.Empty(t, violations, "literal envDefault on yaml-configurable fields; move the default to DefaultConfig")
}

func TestConfig_NameResolverSources(t *testing.T) {
	// no yaml, no env: DefaultConfig value
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, []transform.Source{transform.SourceK8s}, cfg.NameResolver.Sources)

	// yaml must survive env.Parse when the env var is unset
	cfg, err = LoadConfig(bytes.NewBufferString("name_resolver:\n  sources: [k8s, dns, rdns]\n"))
	require.NoError(t, err)
	assert.Equal(t, []transform.Source{transform.SourceK8s, transform.SourceDNS, transform.SourceRDNS}, cfg.NameResolver.Sources)

	// env var wins over yaml
	t.Setenv("OTEL_EBPF_NAME_RESOLVER_SOURCES", "rdns")
	cfg, err = LoadConfig(bytes.NewBufferString("name_resolver:\n  sources: [k8s, dns]\n"))
	require.NoError(t, err)
	assert.Equal(t, []transform.Source{transform.SourceRDNS}, cfg.NameResolver.Sources)
}

func TestConfig_ShutdownTimeout(t *testing.T) {
	t.Setenv("OTEL_EBPF_SHUTDOWN_TIMEOUT", "1m")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, time.Minute, cfg.ShutdownTimeout)
}

func TestConfig_JVMRuntimeMetricsDefaults(t *testing.T) {
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)

	assert.Equal(t, time.Second, cfg.JVMRuntimeMetrics.SamplingInterval)
}

func TestConfig_JVMRuntimeMetricsFromEnv(t *testing.T) {
	t.Setenv("OBI_JVM_RUNTIME_METRICS_SAMPLING_INTERVAL", "250ms")

	cfg, err := LoadConfig(nil)
	require.NoError(t, err)

	assert.Equal(t, 250*time.Millisecond, cfg.JVMRuntimeMetrics.SamplingInterval)
}

func TestConfig_JVMRuntimeMetricsFromYAML(t *testing.T) {
	cfg, err := LoadConfig(bytes.NewBufferString(`
jvm_runtime_metrics:
  sampling_interval: 2s
`))
	require.NoError(t, err)

	assert.Equal(t, 2*time.Second, cfg.JVMRuntimeMetrics.SamplingInterval)
}

// An unknown feature name must abort config loading, not be silently ignored.
// application_jvm is an unknown name most likely to appear in real configs.
func TestConfig_UnknownMetricsFeatureFailsStartup(t *testing.T) {
	_, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features:
    - application_jvm
`))
	require.ErrorContains(t, err, `unknown metrics feature "application_jvm"`)
}

func TestConfigValidate_JVMRuntimeMetricsSamplingInterval(t *testing.T) {
	cfg, err := LoadConfig(bytes.NewBufferString(`
trace_printer: text
executable_path: java
jvm_runtime_metrics:
  sampling_interval: 0s
`))
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jvm_runtime_metrics.sampling_interval")
}

func TestConfig_ExponentialHistogramConfigFromEnv(t *testing.T) {
	t.Setenv("OTEL_EBPF_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SIZE", "96")
	t.Setenv("OTEL_EBPF_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SCALE", "14")

	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)

	assert.Equal(t, int32(96), cfg.OTELMetrics.ExponentialHistogram.MaxSize)
	assert.Equal(t, int32(14), cfg.OTELMetrics.ExponentialHistogram.MaxScale)
}

func TestConfigValidate_ExponentialHistogramConfig(t *testing.T) {
	t.Run("valid scale range", func(t *testing.T) {
		cfg := loadConfig(t, envMap{
			"OTEL_EBPF_EXECUTABLE_PATH":                         "foo",
			"OTEL_EBPF_TRACE_PRINTER":                           "text",
			"OTEL_EBPF_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SCALE": "0",
		})

		require.NoError(t, cfg.Validate())
	})

	t.Run("invalid size", func(t *testing.T) {
		cfg := loadConfig(t, envMap{
			"OTEL_EBPF_EXECUTABLE_PATH":                        "foo",
			"OTEL_EBPF_TRACE_PRINTER":                          "text",
			"OTEL_EBPF_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SIZE": "0",
		})

		require.Error(t, cfg.Validate())
	})

	t.Run("invalid scale", func(t *testing.T) {
		cfg := loadConfig(t, envMap{
			"OTEL_EBPF_EXECUTABLE_PATH":                         "foo",
			"OTEL_EBPF_TRACE_PRINTER":                           "text",
			"OTEL_EBPF_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SCALE": "21",
		})

		require.Error(t, cfg.Validate())
	})
}

func TestConfigValidate(t *testing.T) {
	testCases := []envMap{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "OTEL_EBPF_EXECUTABLE_PATH": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "OTEL_EBPF_EXECUTABLE_PATH": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "localhost:1234", "OTEL_EBPF_EXECUTABLE_PATH": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EBPF_TRACE_PRINTER": "text", "OTEL_EBPF_SHUTDOWN_TIMEOUT": "1m", "OTEL_EBPF_EXECUTABLE_PATH": "foo"},
		{"OTEL_EBPF_TRACE_PRINTER": "json", "OTEL_EBPF_EXECUTABLE_PATH": "foo"},
		{"OTEL_EBPF_TRACE_PRINTER": "json_indent", "OTEL_EBPF_EXECUTABLE_PATH": "foo"},
		{"OTEL_EBPF_TRACE_PRINTER": "counter", "OTEL_EBPF_EXECUTABLE_PATH": "foo"},
		{"OTEL_EBPF_PROMETHEUS_PORT": "8080", "OTEL_EBPF_EXECUTABLE_PATH": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EBPF_INTERNAL_OTEL_METRICS": "true", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "OTEL_EBPF_EXECUTABLE_PATH": "foo"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			require.NoError(t, loadConfig(t, tc).Validate())
		})
	}
}

func TestConfigValidate_ApplicationSizes(t *testing.T) {
	validateFeatures := func(t *testing.T, features string) error {
		t.Helper()
		return loadConfig(t, envMap{
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234",
			"OTEL_EBPF_EXECUTABLE_PATH":           "foo",
			"OTEL_EBPF_METRICS_FEATURES":          features,
		}).Validate()
	}

	t.Run("application without sizes", func(t *testing.T) {
		require.NoError(t, validateFeatures(t, "application"))
	})

	t.Run("application with sizes", func(t *testing.T) {
		require.NoError(t, validateFeatures(t, "application,application_sizes"))
	})

	// on their own the body size histograms have no HTTP metric pipeline to be emitted
	// from, so the configuration is rejected instead of silently emitting nothing
	t.Run("sizes alone is rejected", func(t *testing.T) {
		require.ErrorContains(t, validateFeatures(t, "application_sizes"),
			"application_sizes needs the application RED metrics")
	})

	// a per-service list is joined with the top-level one before it reaches the exporters
	t.Run("sizes per service with top-level application", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
		cfg, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["application"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["application_sizes"]
`))
		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
	})
}

func TestConfigValidate_DeprecatedMetricsFeatureWarning(t *testing.T) {
	captureWarnings := func(t *testing.T, validate func(t *testing.T)) string {
		t.Helper()
		var logs bytes.Buffer
		restore := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
		t.Cleanup(func() { slog.SetDefault(restore) })

		validate(t)
		return logs.String()
	}

	validateWithFeatures := func(t *testing.T, features string) string {
		t.Helper()
		return captureWarnings(t, func(t *testing.T) {
			require.NoError(t, loadConfig(t, envMap{
				"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234",
				"OTEL_EBPF_EXECUTABLE_PATH":           "foo",
				"OTEL_EBPF_METRICS_FEATURES":          features,
			}).Validate())
		})
	}

	t.Run("warns for application_span", func(t *testing.T) {
		logs := validateWithFeatures(t, "application,application_span")
		assert.Contains(t, logs, "feature=application_span")
		assert.Contains(t, logs, "use=application_span_otel")
	})

	// application_span_sizes has no OTel-named equivalent, so it is reported without a
	// replacement rather than pointing at a feature that does not exist.
	t.Run("warns for application_span_sizes without a replacement", func(t *testing.T) {
		logs := validateWithFeatures(t, "application,application_span_sizes")
		assert.Contains(t, logs, "feature=application_span_sizes")
		assert.NotContains(t, logs, "use=")
	})

	t.Run("silent for application_span_otel", func(t *testing.T) {
		assert.NotContains(t, validateWithFeatures(t, "application,application_span_otel"), "deprecated")
	})

	// "all" enables both span-metric formats; the conflict is resolved in favor of OTel,
	// so application_span must not be reported as deprecated anywhere in the output --
	// including inside the conflict-resolution message, which only "all"/"*" ever sees.
	// application_span_sizes is not resolved away and keeps emitting, so it is reported.
	t.Run("all reports only the features that remain enabled", func(t *testing.T) {
		logs := validateWithFeatures(t, "all")
		assert.NotContains(t, logs, "feature=application_span ")
		assert.NotContains(t, logs, "application_span is deprecated")
		assert.Contains(t, logs, "application_span_otel is selected automatically")
		assert.Contains(t, logs, "feature=application_span_sizes")
	})

	// A per-service "all" is joined into the mask that selects the exported metric names,
	// so it must be resolved to OTel just like the top-level list. Otherwise one service
	// saying "all" silently puts every span-metrics service back on the legacy names.
	t.Run("per-service all resolves to otel", func(t *testing.T) {
		var cfg *Config
		logs := captureWarnings(t, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
			loaded, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["application", "application_span_otel"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["all"]
`))
			require.NoError(t, err)
			require.NoError(t, loaded.Validate())
			cfg = loaded
		})

		assert.False(t, cfg.JoinMetricsConfig().Features.LegacySpanMetrics(),
			"per-service all must not select the legacy span metric names")
		assert.NotContains(t, logs, "feature=application_span ")
		assert.Contains(t, logs, "application_span_otel is selected automatically")
	})

	t.Run("explicit legacy and otel per-service is rejected", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
		cfg, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["application"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["application_span", "application_span_otel"]
`))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(), "only enable one format of span metrics")
	})

	// Each mask can be conflict-free while their OR is not: the exporters pick the metric
	// names from the joined mask, so a top-level legacy format with a per-service OTel one
	// would silently select legacy names for the very service that requested OTel.
	t.Run("legacy top-level with otel per-service is rejected", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
		cfg, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["application", "application_span"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["application_span_otel"]
`))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(),
			"across the top-level and per-service metrics features")
	})

	t.Run("otel top-level with legacy per-service is rejected", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
		cfg, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["application", "application_span_otel"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["application_span"]
`))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(),
			"across the top-level and per-service metrics features")
	})

	t.Run("all top-level with legacy per-service is rejected", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
		cfg, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["all"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["application_span"]
`))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(),
			"across the top-level and per-service metrics features")
	})

	t.Run("legacy top-level with all per-service is rejected", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
		cfg, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["application", "application_span"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["*"]
`))
		require.NoError(t, err)
		require.ErrorContains(t, cfg.Validate(),
			"across the top-level and per-service metrics features")
	})

	// Per-service sections feed the exporters through JoinMetricsConfig, so a feature
	// enabled only there must still be reported.
	t.Run("warns for a feature enabled only per-service", func(t *testing.T) {
		logs := captureWarnings(t, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "localhost:1234")
			cfg, err := LoadConfig(bytes.NewBufferString(`
metrics:
  features: ["application"]
discovery:
  instrument:
    - exe_path: foo
      metrics:
        features: ["application_span"]
`))
			require.NoError(t, err)
			require.NoError(t, cfg.Validate())
		})
		assert.Contains(t, logs, "feature=application_span")
		assert.Contains(t, logs, "use=application_span_otel")
	})
}

func TestConfigValidate_error(t *testing.T) {
	testCases := []envMap{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "INSTRUMENT_FUNC_NAME": "bar", "OTEL_EBPF_TRACE_PRINTER": "disabled"},
		{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "INSTRUMENT_FUNC_NAME": "bar", "OTEL_EBPF_TRACE_PRINTER": ""},
		{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "INSTRUMENT_FUNC_NAME": "bar", "OTEL_EBPF_TRACE_PRINTER": "invalid"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			require.Error(t, loadConfig(t, tc).Validate())
		})
	}
}

func TestConfigValidateDiscovery(t *testing.T) {
	userConfig := bytes.NewBufferString(`trace_printer: text
discovery:
  services:
    - name: foo
      k8s_pod_name: tralara
`)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateDiscovery_Errors(t *testing.T) {
	for _, tc := range []string{
		`trace_printer: text
discovery:
  services:
    - name: missing-attributes
`, `trace_printer: text
discovery:
  services:
    - name: invalid-attribute
      k8s_unexisting_stuff: lalala
`,
	} {
		testCaseName := regexp.MustCompile("name: (.+)\n").FindStringSubmatch(tc)[1]
		t.Run(testCaseName, func(t *testing.T) {
			userConfig := bytes.NewBufferString(tc)
			cfg, err := LoadConfig(userConfig)
			require.NoError(t, err)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestConfigValidate_Network_Kube(t *testing.T) {
	userConfig := bytes.NewBufferString(`
otel_metrics_export:
  endpoint: http://otelcol:4318
attributes:
  kubernetes:
    enable: true
  select:
    obi_network_flow_bytes:
      include:
        - k8s.src.name
        - k8s.dst.name
network:
  enable: true
`)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidate_KubeReconnectInitialIntervalZero(t *testing.T) {
	userConfig := bytes.NewBufferString(`
otel_metrics_export:
  endpoint: http://otelcol:4318
trace_printer: text
attributes:
  kubernetes:
    reconnect_initial_interval: 0s
network:
  enable: true
`)

	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)

	err = cfg.Validate()
	require.Error(t, err)

	validate := validator.New(validator.WithRequiredStructEnabled())
	validationErr := validate.Struct(cfg.Attributes.Kubernetes)
	require.Error(t, validationErr)

	var fieldErrs validator.ValidationErrors
	require.ErrorAs(t, validationErr, &fieldErrs)
	require.Len(t, fieldErrs, 1)
	assert.Equal(t, "ReconnectInitialInterval", fieldErrs[0].Field())
	assert.Equal(t, "gt", fieldErrs[0].Tag())
}

func TestConfigValidate_KubeReconnectInitialIntervalOmitted(t *testing.T) {
	userConfig := bytes.NewBufferString(`
otel_metrics_export:
  endpoint: http://otelcol:4318
trace_printer: text
attributes:
  kubernetes:
    enable: true
network:
  enable: true
`)

	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)

	assert.Equal(t, 5*time.Second, cfg.Attributes.Kubernetes.ReconnectInitialInterval)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidate_TracePrinter(t *testing.T) {
	type test struct {
		env      envMap
		errorMsg string
	}

	testCases := []test{
		{
			env:      envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "OTEL_EBPF_TRACE_PRINTER": "invalid_printer"},
			errorMsg: "invalid value for trace_printer: 'invalid_printer'",
		},
		{
			env:      envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo"},
			errorMsg: "you need to define at least one exporter: trace_printer, otel_metrics_export, otel_traces_export or prometheus_export",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.errorMsg, func(t *testing.T) {
			cfg := loadConfig(t, tc.env)

			err := cfg.Validate()
			require.Error(t, err)
			assert.Equal(t, err.Error(), tc.errorMsg)
		})
	}
}

func TestConfigValidate_TracePrinterFallback(t *testing.T) {
	env := envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "OTEL_EBPF_TRACE_PRINTER": "text"}

	cfg := loadConfig(t, env)
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, debug.TracePrinterText, cfg.TracePrinter)
}

func TestConfigValidateForReceiverUsesHostSignalSinks(t *testing.T) {
	cfg := loadConfig(t, envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo"})

	require.ErrorContains(t, cfg.Validate(), "you need to define at least one exporter")
	require.NoError(t, cfg.ValidateForReceiver())

	cfg.TracePrinter = "invalid"
	require.ErrorContains(t, cfg.ValidateForReceiver(), "invalid value for trace_printer")
}

func TestConfigValidateForReceiverUsesHostMetricsForStats(t *testing.T) {
	cfg := loadConfig(t, envMap{})
	cfg.Metrics.Features = export.FeatureStats

	require.ErrorContains(t, cfg.Validate(), "at least one of 'network', 'application' or 'stats'")
	require.NoError(t, cfg.ValidateForReceiver())
}

func TestConfigValidateStaticSkipsHostCompatibility(t *testing.T) {
	cfg := loadConfig(t, envMap{})
	cfg.NetworkFlows.Enable = true
	cfg.NetworkFlows.Source = EbpfSourceTC
	cfg.NetworkFlows.Print = true

	err := cfg.validate(validationContext{
		checkCiliumCompatibility: func(config.TCBackend) error {
			return errors.New("host is incompatible")
		},
	})
	require.ErrorContains(t, err, "host is incompatible")
	require.NoError(t, cfg.ValidateStatic())
}

func TestConfigValidatePrometheusPaths(t *testing.T) {
	testCases := map[string]struct {
		yamlConfig string
		field      string
	}{
		"application metrics": {
			yamlConfig: `open_port: 8080
trace_printer: text
prometheus_export:
  port: 9090
  path: metrics
`,
			field: "Config.Prometheus.Path",
		},
		"internal metrics": {
			yamlConfig: `open_port: 8080
trace_printer: text
internal_metrics:
  prometheus:
    port: 9090
    path: internal/metrics
`,
			field: "Config.InternalMetrics.Prometheus.Path",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadConfig(strings.NewReader(tc.yamlConfig))
			require.NoError(t, err)

			err = cfg.ValidateStatic()
			require.ErrorContains(t, err, tc.field)
			require.ErrorContains(t, err, "'startswith'")
		})
	}
}

func TestConfigValidateRoutes(t *testing.T) {
	userConfig := bytes.NewBufferString(`executable_path: foo
trace_printer: text
routes:
  unmatched: heuristic
  wildcard_char: "*"
`)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateRoutes_Errors(t *testing.T) {
	for _, tc := range []string{
		`executable_path: foo
trace_printer: text
routes:
  unmatched: heuristic
  wildcard_char: "##"
`, `executable_path: foo
trace_printer: text
routes:
  unmatched: heuristic
  wildcard_char: "random"
`,
	} {
		testCaseName := regexp.MustCompile("wildcard_char: (.+)\n").FindStringSubmatch(tc)[1]
		t.Run(testCaseName, func(t *testing.T) {
			userConfig := bytes.NewBufferString(tc)
			cfg, err := LoadConfig(userConfig)
			require.NoError(t, err)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestConfigValidate_SDKLogLevel(t *testing.T) {
	t.Run("lowercase accepted", func(t *testing.T) {
		cfg := loadConfig(t, envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "OTEL_EBPF_TRACE_PRINTER": "text", "OTEL_EBPF_SDK_LOG_LEVEL": "debug"})
		require.NoError(t, cfg.Validate())
	})
	t.Run("uppercase accepted", func(t *testing.T) {
		cfg := loadConfig(t, envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "OTEL_EBPF_TRACE_PRINTER": "text", "OTEL_EBPF_SDK_LOG_LEVEL": "DEBUG"})
		require.NoError(t, cfg.Validate())
	})
	t.Run("mixed case accepted", func(t *testing.T) {
		cfg := loadConfig(t, envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "OTEL_EBPF_TRACE_PRINTER": "text", "OTEL_EBPF_SDK_LOG_LEVEL": "Warn"})
		require.NoError(t, cfg.Validate())
	})
	t.Run("invalid value rejected", func(t *testing.T) {
		cfg := loadConfig(t, envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "OTEL_EBPF_TRACE_PRINTER": "text", "OTEL_EBPF_SDK_LOG_LEVEL": "verbose"})
		require.Error(t, cfg.Validate())
	})
}

func TestConfigValidate_SamplerName(t *testing.T) {
	t.Run("valid sampler accepted", func(t *testing.T) {
		userConfig := bytes.NewBufferString(`executable_path: foo
trace_printer: text
otel_traces_export:
  sampler:
    name: parentbased_always_on
`)
		cfg, err := LoadConfig(userConfig)
		require.NoError(t, err)
		require.NoError(t, cfg.Validate())
	})
	t.Run("invalid sampler rejected", func(t *testing.T) {
		userConfig := bytes.NewBufferString(`executable_path: foo
trace_printer: text
otel_traces_export:
  sampler:
    name: invalid_sampler
`)
		cfg, err := LoadConfig(userConfig)
		require.NoError(t, err)
		require.Error(t, cfg.Validate())
	})
}

func TestConfigValidate_Ports(t *testing.T) {
	t.Run("profile port out of range rejected", func(t *testing.T) {
		cfg := loadConfig(t, envMap{"OTEL_EBPF_EXECUTABLE_PATH": "foo", "OTEL_EBPF_TRACE_PRINTER": "text", "OTEL_EBPF_PROFILE_PORT": "99999"})
		require.Error(t, cfg.Validate())
	})
	t.Run("health check port out of range rejected", func(t *testing.T) {
		userConfig := bytes.NewBufferString(`executable_path: foo
trace_printer: text
health_check:
  port: 99999
`)
		cfg, err := LoadConfig(userConfig)
		require.NoError(t, err)
		require.Error(t, cfg.Validate())
	})
}

func TestHealthCheckListenAddress(t *testing.T) {
	t.Run("defaults to loopback", func(t *testing.T) {
		unsetEnv(t, "OTEL_EBPF_HEALTH_CHECK_LISTEN_ADDRESS")

		cfg, err := LoadConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, health.DefaultListenAddress, cfg.HealthCheck.ListenAddress)
	})

	t.Run("loads external address from YAML", func(t *testing.T) {
		unsetEnv(t, "OTEL_EBPF_HEALTH_CHECK_LISTEN_ADDRESS")
		userConfig := bytes.NewBufferString(`health_check:
  listen_address: 0.0.0.0
  port: 8080
`)

		cfg, err := LoadConfig(userConfig)
		require.NoError(t, err)
		assert.Equal(t, "0.0.0.0", cfg.HealthCheck.ListenAddress)
	})

	t.Run("loads external address from environment", func(t *testing.T) {
		t.Setenv("OTEL_EBPF_HEALTH_CHECK_LISTEN_ADDRESS", "::")

		cfg, err := LoadConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, "::", cfg.HealthCheck.ListenAddress)
	})

	t.Run("rejects non-IP address", func(t *testing.T) {
		cfg := DefaultConfig
		cfg.HealthCheck.ListenAddress = "localhost"
		require.Error(t, cfg.Validate())
	})
}

func TestConfigValidate_RouteHarvesterTimeout(t *testing.T) {
	t.Run("zero timeout rejected", func(t *testing.T) {
		userConfig := bytes.NewBufferString(`executable_path: foo
trace_printer: text
discovery:
  route_harvester_timeout: 0s
`)
		cfg, err := LoadConfig(userConfig)
		require.NoError(t, err)
		require.Error(t, cfg.Validate())
	})
}

func TestConfigValidate_NameResolver(t *testing.T) {
	t.Run("zero cache len rejected", func(t *testing.T) {
		userConfig := bytes.NewBufferString(`executable_path: foo
trace_printer: text
name_resolver:
  cache_len: 0
`)
		cfg, err := LoadConfig(userConfig)
		require.NoError(t, err)
		require.Error(t, cfg.Validate())
	})
	t.Run("zero cache ttl rejected", func(t *testing.T) {
		userConfig := bytes.NewBufferString(`executable_path: foo
trace_printer: text
name_resolver:
  cache_expiry: 0s
`)
		cfg, err := LoadConfig(userConfig)
		require.NoError(t, err)
		require.Error(t, cfg.Validate())
	})
}

func TestConfig_OtelGoAutoEnv(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to OTEL_EBPF_AUTO_TARGET_EXE
	// (Compatibility with OpenTelemetry)
	t.Setenv("OTEL_GO_AUTO_TARGET_EXE", "*testserver")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.AutoTargetExe.MatchString("/bin/testserver"))
}

func TestConfig_TargetPIDs(t *testing.T) {
	t.Run("single PID from env", func(t *testing.T) {
		t.Setenv("OTEL_EBPF_TARGET_PID", "1234")
		cfg, err := LoadConfig(bytes.NewReader(nil))
		require.NoError(t, err)
		assert.Equal(t, services.IntEnum{Ranges: []services.IntRange{{Start: 1234}}}, cfg.TargetPIDs)
		assert.True(t, cfg.Enabled(FeatureAppO11y))
	})
	t.Run("multiple PIDs from env", func(t *testing.T) {
		t.Setenv("OTEL_EBPF_TARGET_PID", "1234,5678,90")
		cfg, err := LoadConfig(bytes.NewReader(nil))
		require.NoError(t, err)
		assert.Equal(t, services.IntEnum{Ranges: []services.IntRange{{Start: 1234}, {Start: 5678}, {Start: 90}}}, cfg.TargetPIDs)
		assert.True(t, cfg.Enabled(FeatureAppO11y))
	})
	t.Run("YAML array", func(t *testing.T) {
		cfg, err := LoadConfig(bytes.NewReader([]byte("target_pids: [11, 22, 33]")))
		require.NoError(t, err)
		assert.Equal(t, services.IntEnum{Ranges: []services.IntRange{{Start: 11}, {Start: 22}, {Start: 33}}}, cfg.TargetPIDs)
	})
	t.Run("YAML single number", func(t *testing.T) {
		cfg, err := LoadConfig(bytes.NewReader([]byte("target_pids: 999")))
		require.NoError(t, err)
		assert.Equal(t, services.IntEnum{Ranges: []services.IntRange{{Start: 999}}}, cfg.TargetPIDs)
	})
}

func TestConfig_NetworkImplicit(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("OTEL_EBPF_METRIC_FEATURES", "network")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(FeatureNetO11y)) // Net o11y should be on
}

func TestConfig_NetworkImplicitProm(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to OTEL_EBPF_EXECUTABLE_PATH
	// (Compatibility with OpenTelemetry)
	t.Setenv("OTEL_EBPF_PROMETHEUS_PORT", "9090")
	t.Setenv("OTEL_EBPF_METRICS_FEATURES", "network")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(FeatureNetO11y)) // Net o11y should be on
}

func TestConfig_AutoLanguageEnv(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to OTEL_EBPF_AUTO_TARGET_EXE
	// (Compatibility with OpenTelemetry)
	t.Setenv("OTEL_EBPF_AUTO_TARGET_LANGUAGE", "{go,java}")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.AutoTargetLanguage.MatchString("java"))
}

func TestConfig_ExternalLogger(t *testing.T) {
	type testCase struct {
		name          string
		handler       func(out io.Writer) slog.Handler
		expectedText  *regexp.Regexp
		expectedCfg   Config
		debugMode     bool
		networkEnable bool
	}
	for _, tc := range []testCase{{
		name: "default info log",
		handler: func(out io.Writer) slog.Handler {
			return slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo})
		},
		expectedText: regexp.MustCompile(
			`^time=\S+ level=INFO msg=information arg=info$`),
	}, {
		name: "default debug log",
		handler: func(out io.Writer) slog.Handler {
			return slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		expectedText: regexp.MustCompile(
			`^time=\S+ level=INFO msg=information arg=info
time=\S+ level=DEBUG msg=debug arg=debug$`),
		debugMode: true,
		expectedCfg: Config{
			TracePrinter: debug.TracePrinterText,
			EBPF:         config.EBPFTracer{BpfDebug: true, ProtocolDebug: true},
		},
	}, {
		name: "debug log with network flows",
		handler: func(out io.Writer) slog.Handler {
			return slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		networkEnable: true,
		expectedText: regexp.MustCompile(
			`^time=\S+ level=INFO msg=information arg=info
time=\S+ level=DEBUG msg=debug arg=debug$`),
		debugMode: true,
		expectedCfg: Config{
			TracePrinter: debug.TracePrinterText,
			EBPF:         config.EBPFTracer{BpfDebug: true, ProtocolDebug: true},
			NetworkFlows: NetworkConfig{Enable: true, Print: true},
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{NetworkFlows: NetworkConfig{Enable: tc.networkEnable}}
			out := &bytes.Buffer{}
			cfg.ExternalLogger(tc.handler(out), tc.debugMode)
			slog.Info("information", "arg", "info")
			slog.Debug("debug", "arg", "debug")
			assert.Regexp(t, tc.expectedText, strings.TrimSpace(out.String()))
			assert.Equal(t, tc.expectedCfg, cfg)
		})
	}
}

func TestDefaultExclusionFilter(t *testing.T) {
	c := DefaultConfig.Discovery.DefaultExcludeInstrument

	assert.True(t, c[0].Path.MatchString("obi"))
	assert.True(t, c[0].Path.MatchString("otelcol-contrib"))

	assert.False(t, c[0].Path.MatchString("/usr/bin/obi/test"))
	assert.False(t, c[0].Path.MatchString("myobi"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/myobi"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/obi-helper"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib/test"))

	assert.True(t, c[0].Path.MatchString("/obi"))
	assert.True(t, c[0].Path.MatchString("/otelcol-contrib"))

	assert.True(t, c[0].Path.MatchString("/usr/bin/obi"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib123"))
}

func TestDefaultLegacyExclusionFilter(t *testing.T) {
	c := DefaultConfig.Discovery.DefaultExcludeServices

	assert.True(t, c[0].Path.MatchString("obi"))
	assert.True(t, c[0].Path.MatchString("otelcol-contrib"))

	assert.False(t, c[0].Path.MatchString("/usr/bin/obi/test"))
	assert.False(t, c[0].Path.MatchString("myobi"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/myobi"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/obi-helper"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib/test"))

	assert.True(t, c[0].Path.MatchString("/obi"))
	assert.True(t, c[0].Path.MatchString("/otelcol-contrib"))

	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib123"))
}

func TestWillUseTC(t *testing.T) {
	env := envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "headers"}
	cfg := loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "disabled"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "all"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "disabled", "OTEL_EBPF_NETWORK_SOURCE": "tc", "OTEL_EBPF_NETWORK_METRICS": "true"}
	cfg = loadConfig(t, env)
	assert.True(t, cfg.willUseTC())
}

func TestConfig_NetworkGuessPortsFromEnv(t *testing.T) {
	cfg := loadConfig(t, envMap{"OTEL_EBPF_NETWORK_GUESS_PORTS": "ordinal"})
	assert.Equal(t, flowdef.PortGuessOrdinal, cfg.NetworkFlows.GuessPorts)
}

func TestConfig_SpanMetricsEnabledForTraces(t *testing.T) {
	tests := []struct {
		name        string
		metrics     otelcfg.MetricsConfig
		prometheus  prom.PrometheusConfig
		mp          perapp.GlobalMetricsConfig
		wantEnabled bool
	}{
		{
			name:        "none enabled",
			metrics:     otelcfg.MetricsConfig{},
			prometheus:  prom.PrometheusConfig{},
			wantEnabled: false,
		},
		{
			name: "otel metrics enabled, but not spans",
			metrics: otelcfg.MetricsConfig{
				MetricsEndpoint: "http://localhost:4318/v1/metrics",
			},
			prometheus:  prom.PrometheusConfig{},
			mp:          perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
			wantEnabled: false,
		},
		{
			name: "otel metrics enabled with spans",
			metrics: otelcfg.MetricsConfig{
				MetricsEndpoint: "http://localhost:4318/v1/metrics",
			},
			prometheus:  prom.PrometheusConfig{},
			mp:          perapp.GlobalMetricsConfig{Features: export.FeatureSpanOTel},
			wantEnabled: true,
		},
		{
			name:    "prometheus metrics enabled, but not spans",
			metrics: otelcfg.MetricsConfig{},
			prometheus: prom.PrometheusConfig{
				Port: 9090,
			},
			mp:          perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
			wantEnabled: false,
		},
		{
			name:    "prometheus span metrics enabled",
			metrics: otelcfg.MetricsConfig{},
			prometheus: prom.PrometheusConfig{
				Port: 9090,
			},
			mp:          perapp.GlobalMetricsConfig{Features: export.FeatureSpanOTel},
			wantEnabled: true,
		},
		{
			name:        "both have features, but not enabled",
			metrics:     otelcfg.MetricsConfig{},
			prometheus:  prom.PrometheusConfig{},
			mp:          perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED | export.FeatureGraph},
			wantEnabled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				OTELMetrics: tc.metrics,
				Prometheus:  tc.prometheus,
				Metrics:     tc.mp,
			}
			got := cfg.SpanMetricsEnabledForTraces()
			assert.Equal(t, tc.wantEnabled, got)
		})
	}
}

func loadConfig(t *testing.T, env envMap) *Config {
	isolatedEnv := envMap{
		"OTEL_EXPORTER_OTLP_ENDPOINT":         "",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "",
		"OTEL_EBPF_PROMETHEUS_PORT":           "0",
	}
	maps.Copy(isolatedEnv, env)
	for k, v := range isolatedEnv {
		t.Setenv(k, v)
	}
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	return cfg
}

func TestNormalizeConfig_MetricFeatures(t *testing.T) {
	type testCase struct {
		name     string
		expected export.Features
		cfg      Config
	}
	testCases := []testCase{{
		name:     "default global meter provider",
		expected: export.FeatureApplicationRED,
		cfg: Config{
			OTELMetrics: otelcfg.MetricsConfig{DeprFeatures: export.FeatureEBPF},
			Prometheus:  prom.PrometheusConfig{DeprFeatures: export.FeatureNetwork},
			Metrics:     perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		},
	}, {
		name:     "OTEL endpoint and legacy features are defined",
		expected: export.FeatureEBPF,
		cfg: Config{
			OTELMetrics: otelcfg.MetricsConfig{MetricsEndpoint: "http://foo", DeprFeatures: export.FeatureEBPF},
			Prometheus:  prom.PrometheusConfig{DeprFeatures: export.FeatureNetwork},
			Metrics:     perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		},
	}, {
		name:     "OTEL endpoint defined but legacy features are not",
		expected: export.FeatureApplicationRED,
		cfg: Config{
			OTELMetrics: otelcfg.MetricsConfig{MetricsEndpoint: "http://foo"},
			Prometheus:  prom.PrometheusConfig{DeprFeatures: export.FeatureNetwork},
			Metrics:     perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		},
	}, {
		name:     "Prom endpoint and legacy features are defined",
		expected: export.FeatureNetwork,
		cfg: Config{
			OTELMetrics: otelcfg.MetricsConfig{DeprFeatures: export.FeatureEBPF},
			Prometheus:  prom.PrometheusConfig{Port: 8080, DeprFeatures: export.FeatureNetwork},
			Metrics:     perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		},
	}, {
		name:     "Prom endpoint defined but legacy features are not",
		expected: export.FeatureApplicationRED,
		cfg: Config{
			OTELMetrics: otelcfg.MetricsConfig{MetricsEndpoint: "http://foo"},
			Prometheus:  prom.PrometheusConfig{Port: 8080},
			Metrics:     perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.normalize()
			assert.Equal(t, tc.expected, cfg.Metrics.Features)
		})
	}
}

func TestNormalizeConfig_Network(t *testing.T) {
	obi := Config{
		NetworkFlows: NetworkConfig{Enable: true},
		Metrics:      perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED},
	}
	obi.normalize()
	assert.Equal(t, export.FeatureApplicationRED|export.FeatureNetwork,
		obi.Metrics.Features)
}

// stringSliceToTextUnmarshalerHookFunc exists so that Features and ExportModes accept a
// YAML sequence as well as the comma-separated text their UnmarshalText parses. Both shapes
// have to decode through confmap, which is how the collector receiver loads the
// configuration; plain YAML loading only ever reaches UnmarshalYAML.
func TestUnmarshalConfmapSequences(t *testing.T) {
	unmarshal := func(t *testing.T, raw map[string]any) *Config {
		t.Helper()
		cfg := DefaultConfig
		require.NoError(t, cfg.Unmarshal(confmap.NewFromStringMap(raw)))
		return &cfg
	}

	t.Run("metrics features", func(t *testing.T) {
		expected := export.FeatureApplicationRED | export.FeatureSpanOTel

		for _, tc := range []struct {
			name  string
			value any
		}{
			{name: "sequence", value: []any{"application", "application_span_otel"}},
			{name: "comma separated", value: "application,application_span_otel"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := unmarshal(t, map[string]any{
					"metrics": map[string]any{"features": tc.value},
				})
				assert.Equal(t, expected, cfg.Metrics.Features)
			})
		}
	})

	t.Run("discovery export modes", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			value any
		}{
			{name: "sequence", value: []any{"metrics", "traces"}},
			{name: "comma separated", value: "metrics,traces"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := unmarshal(t, map[string]any{
					"discovery": map[string]any{"instrument": []any{
						map[string]any{"k8s_namespace": "demo", "exports": tc.value},
					}},
				})
				require.Len(t, cfg.Discovery.Instrument, 1)

				modes := cfg.Discovery.Instrument[0].ExportModes
				assert.True(t, modes.CanExportMetrics())
				assert.True(t, modes.CanExportTraces())
				assert.False(t, modes.CanExportLogs())
			})
		}
	})
}
