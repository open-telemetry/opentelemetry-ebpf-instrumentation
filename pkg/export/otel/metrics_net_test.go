// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestMetricAttributes(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	in := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: ebpf.NetFlowId{
				DstPort: 3210,
				SrcPort: 12345,
			},
		},
		Attrs: ebpf.RecordAttrs{
			SrcName: "srcname",
			DstName: "dstname",
			Metadata: map[attr.Name]string{
				"k8s.src.name":      "srcname",
				"k8s.src.namespace": "srcnamespace",
				"k8s.dst.name":      "dstname",
				"k8s.dst.namespace": "dstnamespace",
			},
		},
	}
	in.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 12, 34, 56, 78}
	in.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 33, 22, 11, 1}

	mcfg := &otelcfg.MetricsConfig{
		MetricsEndpoint:   "http://foo",
		Interval:          10 * time.Millisecond,
		ReportersCacheLen: 100,
		TTL:               5 * time.Minute,
	}
	me, err := newMetricsExporter(t.Context(), &global.ContextInfo{
		MetricAttributeGroups: attributes.GroupKubernetes,
		OTELMetricsExporter:   &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	}, &NetMetricsConfig{
		SelectorCfg: &attributes.SelectorConfig{
			SelectionCfg: map[attributes.Section]attributes.InclusionLists{
				attributes.NetworkFlow.Section: {Include: []string{"*"}},
			},
		},
		Metrics:   mcfg,
		CommonCfg: &mpConfig,
	}, msg.NewQueue[[]*ebpf.Record]())
	require.NoError(t, err)

	_, reportedAttributes := me.flowBytes.ForRecord(in)
	for _, mustContain := range []attribute.KeyValue{
		attribute.String("src.address", "12.34.56.78"),
		attribute.String("dst.address", "33.22.11.1"),
		attribute.String("src.name", "srcname"),
		attribute.String("dst.name", "dstname"),
		attribute.Int("src.port", 12345),
		attribute.Int("dst.port", 3210),

		attribute.String("k8s.src.name", "srcname"),
		attribute.String("k8s.src.namespace", "srcnamespace"),
		attribute.String("k8s.dst.name", "dstname"),
		attribute.String("k8s.dst.namespace", "dstnamespace"),
	} {
		val, ok := reportedAttributes.Value(mustContain.Key)
		assert.Truef(t, ok, "expected %+v in %v", mustContain.Key, reportedAttributes)
		assert.Equal(t, mustContain.Value, val)
	}
}

func TestMetricAttributes_Filter(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	in := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: ebpf.NetFlowId{
				DstPort: 3210,
				SrcPort: 12345,
			},
		},
		Attrs: ebpf.RecordAttrs{
			SrcName: "srcname",
			DstName: "dstname",
			Metadata: map[attr.Name]string{
				"k8s.src.name":      "srcname",
				"k8s.src.namespace": "srcnamespace",
				"k8s.dst.name":      "dstname",
				"k8s.dst.namespace": "dstnamespace",
			},
		},
	}
	in.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 12, 34, 56, 78}
	in.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 33, 22, 11, 1}

	mcfg := &otelcfg.MetricsConfig{
		MetricsEndpoint:   "http://foo",
		Interval:          10 * time.Millisecond,
		ReportersCacheLen: 100,
	}
	me, err := newMetricsExporter(t.Context(), &global.ContextInfo{
		MetricAttributeGroups: attributes.GroupKubernetes,
		OTELMetricsExporter:   &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	},
		&NetMetricsConfig{
			SelectorCfg: &attributes.SelectorConfig{
				SelectionCfg: map[attributes.Section]attributes.InclusionLists{
					attributes.NetworkFlow.Section: {Include: []string{
						"src.address",
						"k8s.src.name",
						"k8s.dst.name",
					}},
				},
			},
			Metrics:   mcfg,
			CommonCfg: &mpConfig,
		}, msg.NewQueue[[]*ebpf.Record]())
	require.NoError(t, err)

	_, reportedAttributes := me.flowBytes.ForRecord(in)
	for _, mustContain := range []attribute.KeyValue{
		attribute.String("src.address", "12.34.56.78"),
		attribute.String("k8s.src.name", "srcname"),
		attribute.String("k8s.dst.name", "dstname"),
	} {
		val, ok := reportedAttributes.Value(mustContain.Key)
		assert.True(t, ok)
		assert.Equal(t, mustContain.Value, val)
	}
	for _, mustNotContain := range []attribute.Key{
		"dst.address",
		"src.name",
		"dst.name",
		"k8s.src.namespace",
		"k8s.dst.namespace",
	} {
		assert.False(t, reportedAttributes.HasValue(mustNotContain))
	}
}

func TestGetFilteredNetworkResourceAttrs(t *testing.T) {
	hostID := "test-host-id"
	attrSelector := attributes.Selection{
		attributes.NetworkFlow.Section: attributes.InclusionLists{
			Include: []string{"*"},
			Exclude: []string{"host.*"},
		},
	}

	attrs := getFilteredNetworkResourceAttrs(hostID, attrSelector)

	expectedAttrs := []string{
		"obi.version",
		"obi.revision",
	}

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	for _, key := range expectedAttrs {
		v, exists := attrMap[key]
		assert.True(t, exists, "Expected attribute %s not found", key)
		assert.NotEmpty(t, v, "Expected attribute %s to have a value", key)
	}

	_, hostIDExists := attrMap["host.id"]
	assert.False(t, hostIDExists, "Host ID should be filtered out")
}
