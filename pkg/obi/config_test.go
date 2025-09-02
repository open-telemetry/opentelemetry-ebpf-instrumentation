// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/components/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/components/imetrics"
	"go.opentelemetry.io/obi/pkg/components/kube"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/cidr"
	"go.opentelemetry.io/obi/pkg/components/traces"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/kubeflags"
	"go.opentelemetry.io/obi/pkg/services"
	"go.opentelemetry.io/obi/pkg/transform"
)

type envMap map[string]string

func TestConfig_Overrides(t *testing.T) {
	userConfig := bytes.NewBufferString(`
trace_printer: json
shutdown_timeout: 30s
channel_buffer_len: 33
ebpf:
  functions:
    - FooBar
otel_metrics_export:
  ttl: 5m
  endpoint: localhost:3030
  buckets:
    duration_histogram: [0, 1, 2]
  histogram_aggregation: base2_exponential_bucket_histogram
prometheus_export:
  ttl: 1s
  buckets:
    request_size_histogram: [0, 10, 20, 22]
    response_size_histogram: [0, 10, 20, 22]
attributes:
  drop_metric_unresolved_ips: false
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

	nc := defaultNetworkConfig
	nc.Enable = true
	nc.AgentIP = "1.2.3.4"
	nc.CIDRs = cidr.Definitions{"10.244.0.0/16"}

	metaSources := maps.Clone(kube.DefaultResourceLabels)
	metaSources["service.namespace"] = []string{"huha.com/yeah"}

	assert.Equal(t, &Config{
		Exec:             cfg.Exec,
		Port:             cfg.Port,
		ServiceName:      "svc-name",
		ChannelBufferLen: 33,
		LogLevel:         "INFO",
		ShutdownTimeout:  30 * time.Second,
		EnforceSysCaps:   false,
		TracePrinter:     "json",
		EBPF: config.EBPFTracer{
			BatchLength:               100,
			BatchTimeout:              time.Second,
			HTTPRequestTimeout:        0,
			TCBackend:                 tcmanager.TCBackendAuto,
			ContextPropagationEnabled: false,
			ContextPropagation:        config.ContextPropagationDisabled,
			RedisDBCache: config.RedisDBCacheConfig{
				Enabled: false,
				MaxSize: 1000,
			},
			BufferSizes: config.EBPFBufferSizes{
				MySQL:    0,
				Postgres: 0,
			},
			MySQLPreparedStatementsCacheSize:    1024,
			PostgresPreparedStatementsCacheSize: 1024,
			MongoRequestsCacheSize:              1024,
		},
		NetworkFlows: nc,
		Metrics: otelcfg.MetricsConfig{
			OTELIntervalMS:    60_000,
			CommonEndpoint:    "localhost:3131",
			MetricsEndpoint:   "localhost:3030",
			Protocol:          otelcfg.ProtocolUnset,
			ReportersCacheLen: ReporterLRUSize,
			Buckets: otelcfg.Buckets{
				DurationHistogram:     []float64{0, 1, 2},
				RequestSizeHistogram:  otelcfg.DefaultBuckets.RequestSizeHistogram,
				ResponseSizeHistogram: otelcfg.DefaultBuckets.ResponseSizeHistogram,
			},
			Features: []string{"application"},
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
			HistogramAggregation: "base2_exponential_bucket_histogram",
			TTL:                  5 * time.Minute,
		},
		Traces: otelcfg.TracesConfig{
			Protocol:          otelcfg.ProtocolUnset,
			CommonEndpoint:    "localhost:3131",
			TracesEndpoint:    "localhost:3232",
			MaxQueueSize:      4096,
			ReportersCacheLen: ReporterLRUSize,
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
		},
		Prometheus: prom.PrometheusConfig{
			Path:     "/metrics",
			Features: []string{otelcfg.FeatureApplication},
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
			TTL:                         time.Second,
			SpanMetricsServiceCacheSize: 10000,
			Buckets: otelcfg.Buckets{
				DurationHistogram:     otelcfg.DefaultBuckets.DurationHistogram,
				RequestSizeHistogram:  []float64{0, 10, 20, 22},
				ResponseSizeHistogram: []float64{0, 10, 20, 22},
			},
		},
		InternalMetrics: imetrics.Config{
			Exporter: imetrics.InternalMetricsExporterDisabled,
			Prometheus: imetrics.PrometheusConfig{
				Port: 3210,
				Path: "/internal/metrics",
			},
		},
		Attributes: Attributes{
			InstanceID: traces.InstanceIDConfig{
				HostnameDNSResolution: true,
			},
			Kubernetes: transform.KubernetesDecorator{
				KubeconfigPath:        "/foo/bar",
				Enable:                kubeflags.EnabledTrue,
				InformersSyncTimeout:  30 * time.Second,
				InformersResyncPeriod: 30 * time.Minute,
				ResourceLabels:        metaSources,
			},
			HostID: HostIDConfig{
				Override:     "the-host-id",
				FetchTimeout: 4 * time.Second,
			},
			Select: attributes.Selection{
				attributes.NetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"foo", "bar"},
					Exclude: []string{"baz", "bae"},
				},
			},
			ExtraGroupAttributes: map[string][]attr.Name{
				"k8s_app_meta": {"k8s.app.version"},
			},
		},
		Routes: &transform.RoutesConfig{
			Unmatch:      transform.UnmatchHeuristic,
			WildcardChar: "*",
		},
		NameResolver: &transform.NameResolverConfig{
			Sources:  []string{"k8s", "dns"},
			CacheLen: 1024,
			CacheTTL: 5 * time.Minute,
		},
		Discovery: services.DiscoveryConfig{
			ExcludeOTelInstrumentedServices: true,
			MinProcessAge:                   5 * time.Second,
			DefaultExcludeServices: services.RegexDefinitionCriteria{
				services.RegexSelector{
					Path: services.NewRegexp("(?:^|/)(beyla$|alloy$|otelcol[^/]*$)"),
				},
				services.RegexSelector{
					Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &k8sDefaultNamespacesRegex},
				},
			},
			DefaultExcludeInstrument: services.GlobDefinitionCriteria{
				services.GlobAttributes{
					Path: services.NewGlob("{*beyla,*alloy,*ebpf-instrument,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}"),
				},
				services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{"k8s_namespace": &k8sDefaultNamespacesGlob},
				},
			},
		},
		NodeJS: NodeJSConfig{
			Enabled: true,
		},
	}, cfg)
}

func TestConfig_ServiceName(t *testing.T) {
	// ServiceName property can be handled via two different env vars OTEL_EBPF_SERVICE_NAME and OTEL_SERVICE_NAME (for
	// compatibility with OpenTelemetry)
	t.Setenv("OTEL_EBPF_SERVICE_NAME", "some-svc-name")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, "some-svc-name", cfg.ServiceName)
}

func TestConfig_ShutdownTimeout(t *testing.T) {
	t.Setenv("OTEL_EBPF_SHUTDOWN_TIMEOUT", "1m")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, time.Minute, cfg.ShutdownTimeout)
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

func TestConfig_OtelGoAutoEnv(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to OTEL_EBPF_AUTO_TARGET_EXE
	// (Compatibility with OpenTelemetry)
	t.Setenv("OTEL_GO_AUTO_TARGET_EXE", "*testserver")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.AutoTargetExe.MatchString("/bin/testserver"))
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
	t.Setenv("OTEL_EBPF_PROMETHEUS_FEATURES", "network")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(FeatureNetO11y)) // Net o11y should be on
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

	assert.True(t, c[0].Path.MatchString("beyla"))
	assert.True(t, c[0].Path.MatchString("alloy"))
	assert.True(t, c[0].Path.MatchString("otelcol-contrib"))

	assert.False(t, c[0].Path.MatchString("/usr/bin/beyla/test"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/alloy/test"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib/test"))

	assert.True(t, c[0].Path.MatchString("/beyla"))
	assert.True(t, c[0].Path.MatchString("/alloy"))
	assert.True(t, c[0].Path.MatchString("/otelcol-contrib"))

	assert.True(t, c[0].Path.MatchString("/usr/bin/beyla"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/alloy"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib123"))
}

func TestDefaultLegacyExclusionFilter(t *testing.T) {
	c := DefaultConfig.Discovery.DefaultExcludeServices

	assert.True(t, c[0].Path.MatchString("beyla"))
	assert.True(t, c[0].Path.MatchString("alloy"))
	assert.True(t, c[0].Path.MatchString("otelcol-contrib"))

	assert.False(t, c[0].Path.MatchString("/usr/bin/beyla/test"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/alloy/test"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib/test"))

	assert.True(t, c[0].Path.MatchString("/beyla"))
	assert.True(t, c[0].Path.MatchString("/alloy"))
	assert.True(t, c[0].Path.MatchString("/otelcol-contrib"))

	assert.True(t, c[0].Path.MatchString("/usr/bin/beyla"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/alloy"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib123"))
}

func TestWillUseTC(t *testing.T) {
	env := envMap{"OTEL_EBPF_BPF_ENABLE_CONTEXT_PROPAGATION": "true"}
	cfg := loadConfig(t, env)
	assert.True(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_ENABLE_CONTEXT_PROPAGATION": "false"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "disabled"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "all"}
	cfg = loadConfig(t, env)
	assert.True(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "headers"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "ip"}
	cfg = loadConfig(t, env)
	assert.True(t, cfg.willUseTC())

	env = envMap{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION": "disabled", "OTEL_EBPF_NETWORK_SOURCE": "tc", "OTEL_EBPF_NETWORK_METRICS": "true"}
	cfg = loadConfig(t, env)
	assert.True(t, cfg.willUseTC())
}

func TestConfig_SpanMetricsEnabledForTraces(t *testing.T) {
	tests := []struct {
		name        string
		metrics     otelcfg.MetricsConfig
		prometheus  prom.PrometheusConfig
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
				Features:        []string{otelcfg.FeatureApplication},
			},
			prometheus:  prom.PrometheusConfig{},
			wantEnabled: false,
		},
		{
			name: "otel metrics enabled with spans",
			metrics: otelcfg.MetricsConfig{
				MetricsEndpoint: "http://localhost:4318/v1/metrics",
				Features:        []string{otelcfg.FeatureSpanOTel},
			},
			prometheus:  prom.PrometheusConfig{},
			wantEnabled: true,
		},
		{
			name:    "prometheus metrics enabled, but not spans",
			metrics: otelcfg.MetricsConfig{},
			prometheus: prom.PrometheusConfig{
				Port:     9090,
				Features: []string{otelcfg.FeatureApplication},
			},
			wantEnabled: false,
		},
		{
			name:    "prometheus span metrics enabled",
			metrics: otelcfg.MetricsConfig{},
			prometheus: prom.PrometheusConfig{
				Port:     9090,
				Features: []string{otelcfg.FeatureGraph},
			},
			wantEnabled: true,
		},
		{
			name: "both have features, but not enabled",
			metrics: otelcfg.MetricsConfig{
				Features: []string{otelcfg.FeatureApplication},
			},
			prometheus: prom.PrometheusConfig{
				Features: []string{otelcfg.FeatureGraph},
			},
			wantEnabled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Metrics:    tc.metrics,
				Prometheus: tc.prometheus,
			}
			got := cfg.SpanMetricsEnabledForTraces()
			assert.Equal(t, tc.wantEnabled, got)
		})
	}
}

func loadConfig(t *testing.T, env envMap) *Config {
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	return cfg
}
