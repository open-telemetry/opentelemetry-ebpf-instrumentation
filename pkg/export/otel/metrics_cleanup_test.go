// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/embedded"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
)

func TestCleanupAllMetricsInstances_RemovesAllMetrics(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	metrics := &Metrics{ctx: ctx}
	meter := &testMeter{}
	reporter := newCleanupTestMetricsReporter(ctx)

	err := reporter.setupMetricExpirers(metrics, meter)
	require.NoError(t, err)

	seeded := seedMetricsExpirers(t, metrics)
	require.NotEmpty(t, seeded)

	metrics.cleanupAllMetricsInstances()

	for _, fieldName := range seeded {
		t.Run(fieldName, func(t *testing.T) {
			assertMetricExpirerCleared(t, metrics, fieldName)
		})
	}
}

type testMeter struct {
	embedded.Meter
}

func (m *testMeter) Int64Counter(string, ...instrument.Int64CounterOption) (instrument.Int64Counter, error) {
	return &testInt64Counter{}, nil
}

func (m *testMeter) Int64UpDownCounter(string, ...instrument.Int64UpDownCounterOption) (instrument.Int64UpDownCounter, error) {
	return nil, nil
}

func (m *testMeter) Int64Histogram(string, ...instrument.Int64HistogramOption) (instrument.Int64Histogram, error) {
	return nil, nil
}

func (m *testMeter) Int64Gauge(string, ...instrument.Int64GaugeOption) (instrument.Int64Gauge, error) {
	return nil, nil
}

func (m *testMeter) Int64ObservableCounter(string, ...instrument.Int64ObservableCounterOption) (instrument.Int64ObservableCounter, error) {
	return nil, nil
}

func (m *testMeter) Int64ObservableUpDownCounter(string, ...instrument.Int64ObservableUpDownCounterOption) (instrument.Int64ObservableUpDownCounter, error) {
	return nil, nil
}

func (m *testMeter) Int64ObservableGauge(string, ...instrument.Int64ObservableGaugeOption) (instrument.Int64ObservableGauge, error) {
	return nil, nil
}

func (m *testMeter) Float64Counter(string, ...instrument.Float64CounterOption) (instrument.Float64Counter, error) {
	return &testFloat64Counter{}, nil
}

func (m *testMeter) Float64UpDownCounter(string, ...instrument.Float64UpDownCounterOption) (instrument.Float64UpDownCounter, error) {
	return nil, nil
}

func (m *testMeter) Float64Histogram(string, ...instrument.Float64HistogramOption) (instrument.Float64Histogram, error) {
	return &testFloat64Histogram{}, nil
}

func (m *testMeter) Float64Gauge(string, ...instrument.Float64GaugeOption) (instrument.Float64Gauge, error) {
	return nil, nil
}

func (m *testMeter) Float64ObservableCounter(string, ...instrument.Float64ObservableCounterOption) (instrument.Float64ObservableCounter, error) {
	return nil, nil
}

func (m *testMeter) Float64ObservableUpDownCounter(string, ...instrument.Float64ObservableUpDownCounterOption) (instrument.Float64ObservableUpDownCounter, error) {
	return nil, nil
}

func (m *testMeter) Float64ObservableGauge(string, ...instrument.Float64ObservableGaugeOption) (instrument.Float64ObservableGauge, error) {
	return nil, nil
}

func (m *testMeter) RegisterCallback(instrument.Callback, ...instrument.Observable) (instrument.Registration, error) {
	return nil, nil
}

type testFloat64Histogram struct {
	embedded.Float64Histogram
}

func (h *testFloat64Histogram) Record(context.Context, float64, ...instrument.RecordOption) {}

func (h *testFloat64Histogram) Remove(context.Context, ...instrument.RemoveOption) {}

type testFloat64Counter struct {
	embedded.Float64Counter
}

func (c *testFloat64Counter) Add(context.Context, float64, ...instrument.AddOption) {}

func (c *testFloat64Counter) Remove(context.Context, ...instrument.RemoveOption) {}

type testInt64Counter struct {
	embedded.Int64Counter
}

func (c *testInt64Counter) Add(context.Context, int64, ...instrument.AddOption) {}

func (c *testInt64Counter) Remove(context.Context, ...instrument.RemoveOption) {}

func newCleanupTestMetricsReporter(ctx context.Context) *MetricsReporter {
	return &MetricsReporter{
		ctx: ctx,
		cfg: &otelcfg.MetricsConfig{
			TTL: time.Minute,
		},
		jointMetricsCfg: &perapp.MetricsConfig{
			Features: export.FeatureApplicationRED | export.FeatureSpanOTel | export.FeatureSpanSizes,
		},
		is: instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
			instrumentations.InstrumentationALL,
		}),
		attrGetters: func(name attr.Name) (attributes.Getter[*request.Span, attribute.KeyValue], bool) {
			return func(*request.Span) attribute.KeyValue {
				return attribute.String(string(name.OTEL()), string(name.OTEL()))
			}, true
		},
	}
}

func seedMetricsExpirers(t *testing.T, metrics *Metrics) []string {
	t.Helper()

	value := reflect.ValueOf(metrics).Elem()
	typ := value.Type()
	seeded := make([]string, 0, typ.NumField())

	for i := 0; i < typ.NumField(); i++ {
		field := value.Field(i)
		fieldType := typ.Field(i)
		if !isSeedableMetricExpirer(field) {
			continue
		}

		seedMetricExpirer(t, field, fieldType.Name)
		seeded = append(seeded, fieldType.Name)
	}

	return seeded
}

func isSeedableMetricExpirer(field reflect.Value) bool {
	return field.Kind() == reflect.Pointer &&
		!field.IsNil() &&
		strings.Contains(field.Type().String(), ".Expirer[")
}

func seedMetricExpirer(t *testing.T, field reflect.Value, fieldName string) {
	t.Helper()

	field = accessibleFieldValue(field)
	results := field.MethodByName("ForRecord").Call([]reflect.Value{reflect.ValueOf(&request.Span{})})
	require.Len(t, results, 2, "seeding expirer %s", fieldName)

	attrs := results[1].Interface().(attribute.Set)
	assert.NotNil(t, attrs)
}

func assertMetricExpirerCleared(t *testing.T, metrics *Metrics, fieldName string) {
	t.Helper()

	field := accessibleFieldValue(reflect.ValueOf(metrics).Elem().FieldByName(fieldName))
	entries := accessibleFieldValue(field.Elem().FieldByName("entries"))
	all := entries.MethodByName("All").Call(nil)
	require.Len(t, all, 1, "reading entries for %s", fieldName)
	assert.Len(t, all[0].Interface(), 0, "expected %s expirer to be empty after cleanup", fieldName)
}

func accessibleFieldValue(field reflect.Value) reflect.Value {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}
