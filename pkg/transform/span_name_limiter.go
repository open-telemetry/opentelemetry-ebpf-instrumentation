package transform

import (
	"context"
	"log/slog"
	"slices"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const aggregatedMark = "AGGREGATED"

type spanNameLimiter struct {
	limit int
	log   *slog.Logger
	in    <-chan []request.Span
	out   *msg.Queue[[]request.Span]

	// key 1: service. Key 2: set of span.names
	spanNamesCount *expirable.LRU[svc.ServiceNameNamespace, map[string]struct{}]
}

type SpanNameLimiterConfig struct {
	Limit int
	OTEL *otelcfg.MetricsConfig
	Prom *prom.PrometheusConfig
}

// SpanNameLimiter applies only to metrics. If span metrics are enabled and
// metric_span_names_limit > 0, it renames all the span.name attributes when the cardinality of that attribute
// for a given, alive service exceeds max_span_names.
func SpanNameLimiter(cfg SpanNameLimiterConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !enabled(&cfg) {
			return swarm.Bypass(input, output)
		}
		log := slog.With("component", "SpanNameLimiter")
		var evictCB func(key svc.ServiceNameNamespace, value map[string]struct{})
		if log.Enabled(ctx, slog.LevelDebug) {
			evictCB = func(key svc.ServiceNameNamespace, value map[string]struct{}) {
				log.Debug("Evicted", "key", key, "value", value)
			}
		}
		return (&spanNameLimiter{
			limit: cfg.Limit,
			log:   log,
			in:    input.Subscribe(),
			out:   output,
			spanNamesCount: expirable.NewLRU(0, evictCB, max(cfg.OTEL.TTL, cfg.Prom.TTL)),
		}).doLimit, nil
	}
}

func enabled(cfg *SpanNameLimiterConfig) bool {
	return cfg.Limit > 0 &&
		(slices.Contains(cfg.OTEL.Features, otelcfg.FeatureSpan) ||
			slices.Contains(cfg.Prom.Features, otelcfg.FeatureSpan))
}

func (l *spanNameLimiter) doLimit(ctx context.Context) {
	l.log.Debug("Starting")
	for {
		select {
		case <-ctx.Done():
			l.log.Debug("context done. Stopping")
			return
		case spans := <-l.in:
			l.aggregate(spans)
			l.out.Send(spans)
		}
	}
}

func (l *spanNameLimiter) aggregate(spans []request.Span) {
	// assuming many spans from the same service could come in a row
	// we can slightly optimize by avoiding the cache lookup for each span
	var lastKey svc.ServiceNameNamespace
	var lastNames map[string]struct{}

	for i := range spans {
		span := &spans[i]
		if key := span.Service.UID.NameNamespace(); key != lastKey {
			lastKey = key
			names, ok := l.spanNamesCount.Get(key)
			if !ok {
				names = map[string]struct{}{}
				l.spanNamesCount.Add(key, names)
			}
			lastNames = names
		}
		if len(lastNames) >= l.limit {
			span.OverrideTraceName = aggregatedMark
			continue
		}
		lastNames[span.TraceName()] = struct{}{}
	}
}
