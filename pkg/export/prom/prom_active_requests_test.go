// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/activerequests"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func TestActiveRequestsPromCollectorGroupingAndTTL(t *testing.T) {
	selector, err := attributes.NewAttrSelector(attributes.GroupPrometheus, &attributes.SelectorConfig{
		UseV2Selection: true,
	})
	require.NoError(t, err)
	attrs := selector.For(attributes.HTTPServerActiveRequests)
	collector := newActiveRequestsCollector(nil, attrs, 2*time.Minute)
	now := time.Unix(100, 0)
	collector.clock = func() time.Time { return now }

	service := svc.Attrs{UID: svc.UID{Name: "checkout", Namespace: "shop", Instance: "instance-1"}}
	first := activerequests.Count{
		Service: service,
		Attributes: attribute.NewSet(
			attribute.String("http.request.method", "GET"),
			attribute.String("url.scheme", "http"),
			attribute.String("job", "shop/checkout"),
			attribute.String("instance", "instance-1"),
		),
		Value: 2,
	}
	second := first
	second.Value = 3

	expectedLabels := map[string]string{
		"http_request_method": "GET",
		"url_scheme":          "http",
		"instance":            "instance-1",
		"job":                 "shop/checkout",
	}
	check := func(metrics []prometheus.Metric, want float64) {
		t.Helper()
		require.Len(t, metrics, 1)
		var point dto.Metric
		require.NoError(t, metrics[0].Write(&point))
		require.InDelta(t, want, point.GetGauge().GetValue(), 0)
		labels := make(map[string]string, len(point.GetLabel()))
		for _, label := range point.GetLabel() {
			labels[label.GetName()] = label.GetValue()
		}
		require.Equal(t, expectedLabels, labels)
	}

	check(collector.collectCounts([]activerequests.Count{first, second}), 5)

	now = now.Add(time.Minute)
	check(collector.collectCounts(nil), 0)

	now = now.Add(time.Minute)
	check(collector.collectCounts(nil), 0)

	now = now.Add(time.Nanosecond)
	require.Empty(t, collector.collectCounts(nil))
}
