// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// injectable function reference for testing

// StatsPrometheusConfig for stat metrics just wraps the global prom.StatsPrometheusConfig as provided by the user
type StatsPrometheusConfig struct {
	Config      *PrometheusConfig
	SelectorCfg *attributes.SelectorConfig
	CommonCfg   *perapp.MetricsConfig
}

// Enabled returns whether the node needs to be activated
func (p StatsPrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.EndpointEnabled() && (p.CommonCfg.Features.StatMetrics())
}

type statMetricsReporter struct {
	cfg *PrometheusConfig

	tcpRtt                *Expirer[prometheus.Histogram]
	tcpFailedConnections  *Expirer[prometheus.Counter]
	tcpRetransmits        *Expirer[prometheus.Counter]
	tcpIo                 *Expirer[prometheus.Counter]
	tcpConnSummarySrtt    *Expirer[prometheus.Histogram]
	tcpConnSummaryMdev    *Expirer[prometheus.Histogram]
	tcpConnSummaryRetrans *Expirer[prometheus.Histogram]
	tcpConnSummaryOoo     *Expirer[prometheus.Histogram]
	tcpConnSummarySegsOut *Expirer[prometheus.Histogram]
	tcpConnSummarySegsIn  *Expirer[prometheus.Histogram]

	promConnect *connector.PrometheusManager

	tcpRttAttrs               []attributes.Field[*ebpf.Stat, string]
	tcpFailedConnectionsAttrs []attributes.Field[*ebpf.Stat, string]
	tcpRetransmitsAttrs       []attributes.Field[*ebpf.Stat, string]
	tcpIoAttrs                []attributes.Field[*ebpf.Stat, string]
	tcpConnSummaryAttrs       []attributes.Field[*ebpf.Stat, string]

	input <-chan []*ebpf.Stat
}

func StatsPrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		reporter, err := newStatsReporter(ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		if cfg.Config.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func newStatsReporter(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) (*statMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("stats Prometheus exporter attributes enable: %w", err)
	}

	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &statMetricsReporter{
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
	}

	var register []prometheus.Collector
	log := slog.With("component", "prom.StatsEndpoint")
	if cfg.CommonCfg.Features.StatsTCPRtt() {
		log.Debug("registering stat tcp rtt metric")

		mr.tcpRttAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPRtt))

		mr.tcpRtt = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatTCPRtt.Prom,
			Help:                            "measures the smoothed TCP RTT as calculated by the kernel in seconds",
			Buckets:                         cfg.Config.Buckets.StatTCPRttHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.tcpRttAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpRtt)
	}

	if cfg.CommonCfg.Features.StatsTCPRetransmits() {
		log.Debug("registering stat tcp retransmits metric")

		mr.tcpRetransmitsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPRetransmits))

		mr.tcpRetransmits = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPRetransmits.Prom,
			Help: "counts the TCP retransmits between 2 endpoints",
		}, labelNames(mr.tcpRetransmitsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpRetransmits)
	}

	if cfg.CommonCfg.Features.StatsTCPIo() {
		log.Debug("registering stat tcp io metric")

		mr.tcpIoAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPIo))

		mr.tcpIo = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPIo.Prom,
			Help: "count bytes transferred at the socket layer",
		}, labelNames(mr.tcpIoAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpIo)
	}

	if cfg.CommonCfg.Features.StatsTCPFailedConnections() {
		log.Debug("registering stat tcp failed connections metric")

		mr.tcpFailedConnectionsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPFailedConnections))

		mr.tcpFailedConnections = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPFailedConnections.Prom,
			Help: "counts the TCP failed connections between 2 endpoints",
		}, labelNames(mr.tcpFailedConnectionsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpFailedConnections)
	}

	if cfg.CommonCfg.Features.StatsTCPConnectionSummary() {
		log.Debug("registering stat tcp connection summary metrics")

		mr.tcpConnSummaryAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPConnectionSummary))

		mr.tcpConnSummarySrtt = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatTCPConnectionSummary.Prom + "_srtt_seconds",
			Help:                            "smoothed RTT at connection close, in seconds",
			Buckets:                         cfg.Config.Buckets.StatTCPRttHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.tcpConnSummaryAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpConnSummarySrtt)

		mr.tcpConnSummaryMdev = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatTCPConnectionSummary.Prom + "_mdev_seconds",
			Help:                            "RTT mean deviation at connection close, in seconds",
			Buckets:                         cfg.Config.Buckets.StatTCPRttHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.tcpConnSummaryAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpConnSummaryMdev)

		mr.tcpConnSummaryRetrans = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    attributes.StatTCPConnectionSummary.Prom + "_retransmits",
			Help:    "total retransmissions at connection close",
			Buckets: []float64{0, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000},
		}, labelNames(mr.tcpConnSummaryAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpConnSummaryRetrans)

		mr.tcpConnSummaryOoo = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    attributes.StatTCPConnectionSummary.Prom + "_ooo_packets",
			Help:    "out-of-order packets received at connection close",
			Buckets: []float64{0, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000},
		}, labelNames(mr.tcpConnSummaryAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpConnSummaryOoo)

		mr.tcpConnSummarySegsOut = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    attributes.StatTCPConnectionSummary.Prom + "_segs_out",
			Help:    "total segments sent at connection close",
			Buckets: prometheus.ExponentialBuckets(1, 4, 8),
		}, labelNames(mr.tcpConnSummaryAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpConnSummarySegsOut)

		mr.tcpConnSummarySegsIn = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    attributes.StatTCPConnectionSummary.Prom + "_segs_in",
			Help:    "total segments received at connection close",
			Buckets: prometheus.ExponentialBuckets(1, 4, 8),
		}, labelNames(mr.tcpConnSummaryAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpConnSummarySegsIn)
	}

	if cfg.Config.Registry != nil {
		cfg.Config.Registry.MustRegister(register...)
	} else {
		mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, register...)
	}

	mr.input = input.Subscribe(msg.SubscriberName("prom.StatsReporterInput"))
	return mr, nil
}

func (r *statMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *statMetricsReporter) collectMetrics(_ context.Context) {
	for stats := range r.input {
		for _, stat := range stats {
			r.observeTCPRtt(stat)
			r.observeTCPFailedConnections(stat)
			r.observeTCPRetransmits(stat)
			r.observeTCPIo(stat)
			r.observeTCPConnectionSummary(stat)
		}
	}
}

func (r *statMetricsReporter) observeTCPRtt(stat *ebpf.Stat) {
	if r.tcpRtt == nil || stat.TCPRtt == nil {
		return
	}
	r.tcpRtt.WithLabelValues(labelValues(stat, r.tcpRttAttrs)...).
		Metric.Observe(float64(stat.TCPRtt.SrttUs) / 1_000_000.0)
}

func (r *statMetricsReporter) observeTCPFailedConnections(stat *ebpf.Stat) {
	if r.tcpFailedConnections == nil || stat.TCPFailedConnection == nil {
		return
	}
	r.tcpFailedConnections.WithLabelValues(labelValues(stat, r.tcpFailedConnectionsAttrs)...).
		Metric.Add(1)
}

func (r *statMetricsReporter) observeTCPRetransmits(stat *ebpf.Stat) {
	if r.tcpRetransmits == nil || !stat.TCPRetransmit {
		return
	}
	r.tcpRetransmits.WithLabelValues(labelValues(stat, r.tcpRetransmitsAttrs)...).
		Metric.Add(1)
}

func (r *statMetricsReporter) observeTCPIo(stat *ebpf.Stat) {
	if r.tcpIo == nil || stat.TCPIo == nil {
		return
	}
	r.tcpIo.WithLabelValues(labelValues(stat, r.tcpIoAttrs)...).
		Metric.Add(float64(stat.TCPIo.Bytes))
}

func (r *statMetricsReporter) observeTCPConnectionSummary(stat *ebpf.Stat) {
	cs := stat.TCPConnectionSummary
	if cs == nil {
		return
	}
	labels := labelValues(stat, r.tcpConnSummaryAttrs)
	if r.tcpConnSummarySrtt != nil {
		r.tcpConnSummarySrtt.WithLabelValues(labels...).
			Metric.Observe(float64(cs.SrttUs) / 1_000_000.0)
	}
	if r.tcpConnSummaryMdev != nil {
		r.tcpConnSummaryMdev.WithLabelValues(labels...).
			Metric.Observe(float64(cs.MdevUs) / 1_000_000.0)
	}
	if r.tcpConnSummaryRetrans != nil {
		r.tcpConnSummaryRetrans.WithLabelValues(labels...).
			Metric.Observe(float64(cs.TotalRetrans))
	}
	if r.tcpConnSummaryOoo != nil {
		r.tcpConnSummaryOoo.WithLabelValues(labels...).
			Metric.Observe(float64(cs.RcvOoopack))
	}
	if r.tcpConnSummarySegsOut != nil {
		r.tcpConnSummarySegsOut.WithLabelValues(labels...).
			Metric.Observe(float64(cs.SegsOut))
	}
	if r.tcpConnSummarySegsIn != nil {
		r.tcpConnSummarySegsIn.WithLabelValues(labels...).
			Metric.Observe(float64(cs.SegsIn))
	}
}
