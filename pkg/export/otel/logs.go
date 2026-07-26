// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"

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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/logsgen"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func ologslog() *slog.Logger {
	return slog.With("component", "otel.LogsReceiver")
}

func makeLogsReceiver(
	cfg otelcfg.LogsConfig,
	tracesCfg otelcfg.TracesConfig,
	ctxInfo *global.ContextInfo,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) *logsOTELReceiver {
	return &logsOTELReceiver{
		cfg:            cfg,
		tracesCfg:      tracesCfg,
		ctxInfo:        ctxInfo,
		selectorCfg:    selectorCfg,
		is:             instrumentations.NewInstrumentationSelection(tracesCfg.Instrumentations),
		input:          input.Subscribe(msg.SubscriberName("otel.LogsReceiver")),
		attributeCache: expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
	}
}

// LogsReceiver creates a terminal node that consumes request.Spans and sends
// queue/processing log records to the configured logs consumer. It shares
// the InstrumentationSelection and Sampler with the traces pipeline
// (tracesCfg), so a request's log record is subject to the exact same
// accept/sample decision as its trace.
func LogsReceiver(
	ctxInfo *global.ContextInfo,
	cfg otelcfg.LogsConfig,
	tracesCfg otelcfg.TracesConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() || !cfg.QueueProcessingLogs {
			return swarm.EmptyRunFunc()
		}
		lr := makeLogsReceiver(cfg, tracesCfg, ctxInfo, selectorCfg, input)
		return lr.provideLoop, nil
	}
}

type logsOTELReceiver struct {
	cfg            otelcfg.LogsConfig
	tracesCfg      otelcfg.TracesConfig
	ctxInfo        *global.ContextInfo
	selectorCfg    *attributes.SelectorConfig
	is             instrumentations.InstrumentationSelection
	attributeCache *expirable2.LRU[svc.UID, []attribute.KeyValue]
	input          <-chan []request.Span
}

func (lr *logsOTELReceiver) getConstantAttributes() (map[attr.Name]struct{}, error) {
	return tracesgen.UserSelectedAttributes(lr.selectorCfg)
}

func (lr *logsOTELReceiver) processSpans(ctx context.Context, exp exporter.Logs, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler) {
	spanGroups := tracesgen.GroupSpans(ctx, spans, traceAttrs, sampler, lr.is, lr.selectorCfg.SensitiveQueryParamsCfg.Effective()...)

	for _, spanGroup := range spanGroups {
		if len(spanGroup) == 0 {
			continue
		}
		sample := spanGroup[0]
		if !sample.Span.Service.ExportModes.CanExportLogs() {
			continue
		}

		envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
		logs := logsgen.GenerateLogs(
			lr.attributeCache,
			&sample.Span.Service,
			envResourceAttrs,
			&lr.ctxInfo.NodeMeta,
			spanGroup,
			reporterName,
		)
		if logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len() == 0 {
			continue
		}
		err := exp.ConsumeLogs(ctx, logs)
		if err != nil {
			if err.Error() == "sending queue is full" {
				slog.Debug("error sending log record to consumer", "error", err)
			} else {
				slog.Warn("error sending log record to consumer", "error", err)
			}
		}
	}
}

func (lr *logsOTELReceiver) provideLoop(ctx context.Context) {
	exp, host, err := getLogsExporter(ctx, lr.cfg)
	if err != nil {
		slog.Error("error creating logs exporter", "error", err)
		return
	}
	defer func() {
		if err := exp.Shutdown(ctx); err != nil {
			slog.Error("error shutting down logs exporter", "error", err)
		}
	}()
	if err := exp.Start(ctx, host); err != nil {
		slog.Error("error starting logs exporter", "error", err)
		return
	}

	traceAttrs, err := lr.getConstantAttributes()
	if err != nil {
		slog.Error("error selecting user trace attributes", "error", err)
		return
	}

	sampler := lr.tracesCfg.SamplerConfig.Implementation()
	swarms.ForEachInput(ctx, lr.input, ologslog().Debug, func(spans []request.Span) {
		lr.processSpans(ctx, exp, spans, traceAttrs, sampler)
	})
}

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
		opts, err := otelcfg.HTTPLogsEndpointOptions(&cfg)
		if err != nil {
			slog.Error("can't get HTTP logs endpoint options", "error", err)
			return nil, nil, err
		}
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		config.QueueConfig = getLogsQueueConfig(cfg)
		config.RetryConfig = getLogsRetrySettings(cfg)
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
		set := getTraceSettings(factory.Type(), cfg.SDKLogLevel)
		exp, err := factory.CreateLogs(ctx, set, config)
		if err != nil {
			slog.Error("can't create OTLP HTTP logs exporter", "error", err)
			return nil, nil, err
		}
		wrapped, err := exporterhelper.NewLogs(ctx, set, cfg,
			exp.ConsumeLogs,
			exporterhelper.WithStart(exp.Start),
			exporterhelper.WithShutdown(exp.Shutdown),
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
			exporterhelper.WithQueue(config.QueueConfig),
			exporterhelper.WithRetry(config.RetryConfig))
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
