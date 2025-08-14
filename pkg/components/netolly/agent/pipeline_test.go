// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/components/connector"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/flow"
	"go.opentelemetry.io/obi/pkg/components/netolly/flow/transport"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	prom2 "go.opentelemetry.io/obi/test/integration/components/prom"
)

const timeout = 5 * time.Second

type DummyFlowFetcher struct {
	records []ebpf.NetFlowRecordT
	idx     int
}

func NewDummyFlowFetcher() *DummyFlowFetcher {
	d := DummyFlowFetcher{}

	d.add(transport.UDP, 123, 456)
	d.add(transport.TCP, 789, 1011)
	d.add(transport.UDP, 333, 444)
	d.add(transport.TCP, 1213, 1415)
	d.add(transport.UDP, 3333, 8080)

	d.idx = 0

	return &d
}

func (d *DummyFlowFetcher) add(protocol transport.Protocol, srcPort, dstPort uint16) {
	record := ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{
			SrcPort: srcPort, DstPort: dstPort, TransportProtocol: uint8(protocol),
		},
	}

	d.records = append(d.records, record)
}

func (d *DummyFlowFetcher) ReadInto(r *ringbuf.Record) error {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, d.records[d.idx])
	if err != nil {
		panic(err)
	}

	r.RawSample = buf.Bytes()

	d.idx = (d.idx + 1) % len(d.records)

	return nil
}

func TestFilter(t *testing.T) {
	ctx := t.Context()

	promPort, err := test.FreeTCPPort()
	require.NoError(t, err)

	// Flows pipeline that will discard any network flow not matching the "TCP" transport attribute
	flows := Flows{
		ctxInfo: &global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{
				Path:     "/metrics",
				Port:     promPort,
				Features: []string{otelcfg.FeatureNetwork},
				TTL:      time.Hour,
			},
			Filters: filter.AttributesConfig{
				Network: map[string]filter.MatchDefinition{"transport": {Match: "TCP"}},
			},
			Attributes: obi.Attributes{Select: attributes.Selection{
				attributes.NetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "iface.direction", "dst_port", "iface", "src_port", "transport"},
				},
			}},
		},
	}

	ifaceNamer := func(int) string {
		return "fakeiface"
	}

	flowFetcher := NewDummyFlowFetcher()

	tracer, err := flow.NewRingBufTracer(flowFetcher, flows.cfg,
		flows.ctxInfo.K8sInformer, "1.2.3.4", ifaceNamer)

	require.NoError(t, err)

	flows.rbTracer = tracer

	runner, err := flows.buildPipeline(ctx)
	require.NoError(t, err)

	go runner.Start(ctx)

	test.Eventually(t, timeout, func(t require.TestingT) {
		metrics, err := prom2.Scrape(fmt.Sprintf("http://localhost:%d/metrics", promPort))
		require.NoError(t, err)

		// assuming metrics returned alphabetically ordered
		assert.Equal(t, []prom2.ScrapedMetric{
			{Name: "obi_network_flow_bytes_total", Labels: map[string]string{
				"obi_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1011", "iface": "fakeiface", "src_port": "789", "transport": "TCP",
			}},
			{Name: "obi_network_flow_bytes_total", Labels: map[string]string{
				"obi_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1415", "iface": "fakeiface", "src_port": "1213", "transport": "TCP",
			}},
			// standard prometheus metrics. Leaving them here to simplify test verification
			{Name: "promhttp_metric_handler_errors_total", Labels: map[string]string{"cause": "encoding"}},
			{Name: "promhttp_metric_handler_errors_total", Labels: map[string]string{"cause": "gathering"}},
		}, metrics)
	})
}
