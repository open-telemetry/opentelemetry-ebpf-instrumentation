// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configmiddleware"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/debugexporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

// emptyHost, udsHost, udsMiddleware, createZapLoggerDev, and getTraceSettings
// are defined in traces.go (same package) and reused here unchanged.

//nolint:cyclop
func getLogsExporter(ctx context.Context, cfg otelcfg.LogsConfig) (exporter.Logs, component.Host, error) {
	if cfg.LogsConsumer != nil {
		newType, err := component.NewType("logs")
		if err != nil {
			return nil, nil, err
		}
		set := getTraceSettings(newType, cfg.SDKLogLevel)
		exp, err := exporterhelper.NewLogs(ctx, set, cfg,
			cfg.LogsConsumer.ConsumeLogs,
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		)
		if err != nil {
			return nil, nil, err
		}
		return exp, emptyHost{}, nil
	}
	switch proto := cfg.GetProtocol(); proto {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "":
		slog.Debug("instantiating HTTP LogsReporter", "protocol", proto)
		factory := otlphttpexporter.NewFactory()
		config, host, queueCfg, retryCfg, err := buildHTTPLogsExporterConfig(cfg, factory)
		if err != nil {
			slog.Error("can't get HTTP logs endpoint options", "error", err)
			return nil, nil, err
		}
		set := getTraceSettings(factory.Type(), cfg.SDKLogLevel)
		exp, err := factory.CreateLogs(ctx, set, config)
		if err != nil {
			slog.Error("can't create OTLP HTTP logs exporter", "error", err)
			return nil, nil, err
		}
		// The inner exporter's own queue/retry are disabled by
		// buildHTTPLogsExporterConfig; queueCfg/retryCfg are applied here so
		// there is exactly one buffering/retry layer, matching getTracesExporter.
		wrapped, err := exporterhelper.NewLogs(ctx, set, cfg,
			exp.ConsumeLogs,
			exporterhelper.WithStart(exp.Start),
			exporterhelper.WithShutdown(exp.Shutdown),
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
			exporterhelper.WithQueue(queueCfg),
			exporterhelper.WithRetry(retryCfg))
		return wrapped, host, err
	case otelcfg.ProtocolGRPC:
		slog.Debug("instantiating GRPC LogsReporter", "protocol", proto)
		opts, err := otelcfg.GRPCLogsEndpointOptions(&cfg)
		if err != nil {
			slog.Error("can't get GRPC logs endpoint options", "error", err)
			return nil, nil, err
		}
		grpcEndpoint := opts.Endpoint
		if opts.UnixSocketAddr == "" {
			endpoint, _, perr := otelcfg.ParseLogsEndpoint(&cfg)
			if perr != nil {
				slog.Error("can't parse GRPC logs endpoint", "error", perr)
				return nil, nil, perr
			}
			grpcEndpoint = endpoint.String()
		}
		factory := otlpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlpexporter.Config)
		config.QueueConfig = getLogsQueueConfig(cfg)
		config.RetryConfig = getLogsRetrySettings(cfg)
		config.ClientConfig = configgrpc.ClientConfig{
			Endpoint: grpcEndpoint,
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		set := getTraceSettings(factory.Type(), cfg.SDKLogLevel)
		exp, err := factory.CreateLogs(ctx, set, config)
		if err != nil {
			return nil, nil, err
		}
		return exp, emptyHost{}, nil
	case otelcfg.ProtocolDebug:
		slog.Debug("instantiating Debug LogsReporter", "protocol", proto)
		factory := debugexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*debugexporter.Config)
		config.UseInternalLogger = false
		config.Verbosity = configtelemetry.LevelDetailed
		set := getTraceSettings(factory.Type(), cfg.SDKLogLevel)
		exp, err := factory.CreateLogs(ctx, set, config)
		if err != nil {
			return nil, nil, err
		}
		return exp, emptyHost{}, nil
	default:
		slog.Error(fmt.Sprintf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, otelcfg.ProtocolGRPC, otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf))
		return nil, nil, fmt.Errorf("invalid protocol value: %q", proto)
	}
}

// buildHTTPLogsExporterConfig builds the otlphttpexporter.Config for the HTTP logs
// exporter, with its own queue and retry disabled, and separately returns the real
// queue/retry settings for the caller to apply exactly once via the outer
// exporterhelper.NewLogs wrap — mirroring getTracesExporter's HTTP branch, so a log
// record is buffered and retried by a single layer instead of the inner exporter and
// the outer wrap each doing it independently. Split out from getLogsExporter so this
// disable-then-wrap-once behavior is directly testable.
func buildHTTPLogsExporterConfig(cfg otelcfg.LogsConfig, factory exporter.Factory) (
	*otlphttpexporter.Config,
	component.Host,
	configoptional.Optional[exporterhelper.QueueBatchConfig],
	configretry.BackOffConfig,
	error,
) {
	opts, err := otelcfg.HTTPLogsEndpointOptions(&cfg)
	if err != nil {
		return nil, nil, configoptional.None[exporterhelper.QueueBatchConfig](), configretry.BackOffConfig{}, err
	}

	config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
	queueCfg := getLogsQueueConfig(cfg)
	retryCfg := getLogsRetrySettings(cfg)
	disabledRetry := configretry.NewDefaultBackOffConfig()
	disabledRetry.Enabled = false
	config.QueueConfig = configoptional.None[exporterhelper.QueueBatchConfig]()
	config.RetryConfig = disabledRetry
	config.ClientConfig = confighttp.ClientConfig{
		Endpoint: opts.Scheme + "://" + opts.Endpoint + opts.BaseURLPath,
		TLS: configtls.ClientConfig{
			Insecure:           opts.Insecure,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		Headers: convertHeaders(opts.Headers),
	}

	host := component.Host(emptyHost{})
	if opts.UnixSocketAddr != "" {
		mwID := component.MustNewID("obi_uds")
		config.ClientConfig.Middlewares = []configmiddleware.Config{{ID: mwID}}
		host = udsHost{extensions: map[component.ID]component.Component{
			mwID: udsMiddleware{addr: opts.UnixSocketAddr},
		}}
	}

	return config, host, queueCfg, retryCfg, nil
}

func getLogsQueueConfig(cfg otelcfg.LogsConfig) configoptional.Optional[exporterhelper.QueueBatchConfig] {
	if cfg.BatchMaxSize <= 0 && cfg.BatchTimeout <= 0 && cfg.QueueSize <= 0 {
		return configoptional.None[exporterhelper.QueueBatchConfig]()
	}

	queueConfig := exporterhelper.NewDefaultQueueConfig()
	queueConfig.Sizer = exporterhelper.RequestSizerTypeItems
	queueConfig.BlockOnOverflow = true
	if cfg.QueueSize > 0 {
		queueConfig.QueueSize = int64(cfg.QueueSize)
	}
	batchCfg := exporterhelper.BatchConfig{
		Sizer: queueConfig.Sizer,
	}
	batchSet := false
	if cfg.BatchMaxSize > 0 {
		batchSet = true
		batchCfg.MaxSize = int64(cfg.BatchMaxSize)
	}
	if cfg.BatchTimeout > 0 {
		batchSet = true
		batchCfg.FlushTimeout = cfg.BatchTimeout
		batchCfg.MinSize = int64(cfg.BatchMaxSize)
	}
	if batchSet {
		queueConfig.Batch = configoptional.Some(batchCfg)
	}
	return configoptional.Some(queueConfig)
}

func getLogsRetrySettings(cfg otelcfg.LogsConfig) configretry.BackOffConfig {
	backOffCfg := configretry.NewDefaultBackOffConfig()
	if cfg.BackOffInitialInterval > 0 {
		backOffCfg.InitialInterval = cfg.BackOffInitialInterval
	}
	if cfg.BackOffMaxInterval > 0 {
		backOffCfg.MaxInterval = cfg.BackOffMaxInterval
	}
	if cfg.BackOffMaxElapsedTime > 0 {
		backOffCfg.MaxElapsedTime = cfg.BackOffMaxElapsedTime
	}
	return backOffCfg
}
