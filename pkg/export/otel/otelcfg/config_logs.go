// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import (
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/consumer"
)

func llog() *slog.Logger {
	return slog.With("component", "otelcfg.LogsConfig")
}

type LogsConfig struct {
	LogsConsumer   consumer.Logs `yaml:"-"`
	CommonEndpoint string        `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT" jsonschema:"format=uri"`
	LogsEndpoint   string        `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT" jsonschema:"format=uri"`

	Protocol     Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	LogsProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"`

	// InsecureSkipVerify enables skipping TLS certificate verification (not standard, so we don't follow the same naming convention)
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_EBPF_INSECURE_SKIP_VERIFY"`

	// BatchMaxSize is the maximum number of log records that the batcher will accumulate
	// before flushing a batch to the sending queue.
	BatchMaxSize int `yaml:"batch_max_size" env:"OTEL_EBPF_OTLP_LOGS_BATCH_MAX_SIZE" validate:"omitempty,gt=0"`

	// QueueSize is the maximum number of log records that the sending queue will hold
	// before applying back-pressure. It must be >= `2 * BatchMaxSize`, otherwise the
	// memory queue rejects every batch with "element size too large" and drops
	// log records permanently. If left at 0 it defaults to `4 * BatchMaxSize`.
	QueueSize int `yaml:"queue_size" env:"OTEL_EBPF_OTLP_LOGS_QUEUE_SIZE"`

	// BatchTimeout is the time after which a batch will be sent regardless of its size.
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"OTEL_EBPF_OTLP_LOGS_BATCH_TIMEOUT"`

	// Configuration options for BackOffConfig of the logs exporter.
	// See https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configretry/backoff.go
	// Namespaced per-signal (unlike TracesConfig's generically-named
	// equivalents) since this is a new signal and there's no existing
	// precedent of these being intentionally shared across signals.
	BackOffInitialInterval time.Duration `yaml:"backoff_initial_interval" env:"OTEL_EBPF_LOGS_BACKOFF_INITIAL_INTERVAL" validate:"omitempty,gt=0"`
	BackOffMaxInterval     time.Duration `yaml:"backoff_max_interval" env:"OTEL_EBPF_LOGS_BACKOFF_MAX_INTERVAL" validate:"omitempty,gt=0"`
	BackOffMaxElapsedTime  time.Duration `yaml:"backoff_max_elapsed_time" env:"OTEL_EBPF_LOGS_BACKOFF_MAX_ELAPSED_TIME" validate:"omitempty,gt=0"`
	ReportersCacheLen      int           `yaml:"reporters_cache_len" env:"OTEL_EBPF_LOGS_REPORT_CACHE_LEN" validate:"omitempty,gt=0"`

	// SDKLogLevel is intentionally the SAME env var as TracesConfig/MetricsConfig's
	// field of the same name — this is an existing shared, not per-signal, knob.
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"OTEL_EBPF_SDK_LOG_LEVEL" validate:"omitempty,oneofci=debug info warn error"`

	// OTLPEndpointProvider allows overriding the OTLP Endpoint. It needs to return an endpoint and
	// a boolean indicating if the endpoint is common for both traces and metrics
	OTLPEndpointProvider func() (string, bool) `yaml:"-" env:"-"`

	// InjectHeaders allows injecting custom headers to the HTTP OTLP exporter
	InjectHeaders func(dst map[string]string) `yaml:"-" env:"-"`
}

func (m *LogsConfig) NormalizeQueueConfig() error {
	if m.QueueSize == 0 && m.BatchMaxSize > 0 {
		m.QueueSize = 4 * m.BatchMaxSize
		llog().Info("logs.queue_size not set, defaulting to 4 * batch_max_size",
			"queue_size", m.QueueSize, "batch_max_size", m.BatchMaxSize)
	}
	if m.BatchMaxSize > 0 && m.QueueSize < 2*m.BatchMaxSize {
		return fmt.Errorf("logs.queue_size (%d) must be >= 2 * logs.batch_max_size (%d): "+
			"otherwise the sending queue rejects every batch with \"element size too large\"",
			m.QueueSize, m.BatchMaxSize)
	}
	return nil
}

func (m LogsConfig) MarshalYAML() (any, error) {
	omit := map[string]struct{}{
		"endpoint": {},
	}
	return omitFieldsForYAML(m, omit), nil
}

// Enabled specifies that the OTEL logs node is enabled if and only if
// either the OTEL endpoint and OTEL logs endpoint is defined.
// If not enabled, this node won't be instantiated
func (m *LogsConfig) Enabled() bool {
	if m.LogsConsumer != nil {
		return true
	}

	if m.LogsProtocol == ProtocolDebug || (m.LogsProtocol == "" && m.Protocol == ProtocolDebug) {
		return true
	}

	ep, _ := m.OTLPLogsEndpoint()
	return ep != ""
}

func (m *LogsConfig) GetProtocol() Protocol {
	if m.LogsConsumer != nil {
		return ProtocolUnset
	}
	if m.LogsProtocol != "" {
		return m.LogsProtocol
	}
	if m.Protocol != "" {
		return m.Protocol
	}
	return m.guessProtocol()
}

func (m *LogsConfig) OTLPLogsEndpoint() (string, bool) {
	if m.OTLPEndpointProvider != nil {
		return m.OTLPEndpointProvider()
	}
	return ResolveOTLPEndpoint(m.LogsEndpoint, m.CommonEndpoint)
}

func (m *LogsConfig) guessProtocol() Protocol {
	ep, _, err := ParseLogsEndpoint(m)
	if err == nil {
		if strings.HasSuffix(ep.Port(), UsualPortGRPC) {
			return ProtocolGRPC
		} else if strings.HasSuffix(ep.Port(), UsualPortHTTP) {
			return ProtocolHTTPProtobuf
		}
	}
	return ProtocolHTTPProtobuf
}

// ParseLogsEndpoint defines the HTTP path of the logs collector.
func ParseLogsEndpoint(cfg *LogsConfig) (*url.URL, bool, error) {
	endpoint, isCommon := cfg.OTLPLogsEndpoint()

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, isCommon, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, isCommon, fmt.Errorf("URL %q must have a scheme and a host", endpoint)
	}
	return murl, isCommon, nil
}

func unixLogsHTTPOptions(cfg *LogsConfig, addr string) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	if err := validateUnixSocketAddr(addr); err != nil {
		return opts, err
	}

	setLogsProtocol(cfg)
	opts.UnixSocketAddr = addr
	opts.Scheme = "http"
	opts.Endpoint = "localhost"
	opts.Insecure = true

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envLogsHeaders))

	return opts, nil
}

func unixLogsGRPCOptions(cfg *LogsConfig, addr string) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	if err := validateUnixSocketAddr(addr); err != nil {
		return opts, err
	}

	opts.UnixSocketAddr = addr
	opts.Endpoint = grpcUnixTarget(addr)
	opts.Insecure = true

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envLogsHeaders))

	return opts, nil
}

func HTTPLogsEndpointOptions(cfg *LogsConfig) (OTLPOptions, error) {
	rawEndpoint, _ := cfg.OTLPLogsEndpoint()
	if addr, ok := unixSocketEndpoint(rawEndpoint); ok {
		return unixLogsHTTPOptions(cfg, addr)
	}

	opts := OTLPOptions{Headers: map[string]string{}}
	log := llog().With("transport", "http")

	murl, isCommon, err := ParseLogsEndpoint(cfg)
	if err != nil {
		return opts, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "logsProtocol", cfg.LogsProtocol, "endpoint", murl.Host)
	setLogsProtocol(cfg)
	opts.Scheme = murl.Scheme
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	opts.URLPath = strings.TrimSuffix(murl.Path, "/")
	opts.BaseURLPath = strings.TrimSuffix(opts.URLPath, "/v1/logs")
	if isCommon {
		opts.URLPath += "/v1/logs"
		log.Debug("Specifying path", "path", opts.URLPath)
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envLogsHeaders))

	return opts, nil
}

func GRPCLogsEndpointOptions(cfg *LogsConfig) (OTLPOptions, error) {
	rawEndpoint, _ := cfg.OTLPLogsEndpoint()
	if addr, ok := unixSocketEndpoint(rawEndpoint); ok {
		return unixLogsGRPCOptions(cfg, addr)
	}

	opts := OTLPOptions{Headers: map[string]string{}}
	log := llog().With("transport", "grpc")
	murl, _, err := ParseLogsEndpoint(cfg)
	if err != nil {
		return opts, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "logsProtocol", cfg.LogsProtocol, "endpoint", murl.Host)
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envLogsHeaders))
	return opts, nil
}

func setLogsProtocol(cfg *LogsConfig) {
	if _, ok := os.LookupEnv(envLogsProtocol); ok {
		return
	}
	if _, ok := os.LookupEnv(envProtocol); ok {
		return
	}
	if cfg.LogsProtocol != "" {
		os.Setenv(envLogsProtocol, string(cfg.LogsProtocol))
		return
	}
	if cfg.Protocol != "" {
		os.Setenv(envProtocol, string(cfg.Protocol))
		return
	}
	os.Setenv(envLogsProtocol, string(cfg.guessProtocol()))
}
