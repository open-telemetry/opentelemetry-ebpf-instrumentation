// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/test/collector"
)

var fakeMux = sync.Mutex{}

func TestMetrics_InternalInstrumentation(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	// fake OTEL collector server
	coll := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer coll.Close()
	// Wait for the HTTP server to be alive
	test.Eventually(t, timeout, func(t require.TestingT) {
		resp, err := coll.Client().Get(coll.URL + "/foo")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Run the metrics reporter node standalone
	exportMetrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	internalMetrics := &fakeInternalMetrics{}
	mcfg := &otelcfg.MetricsConfig{
		CommonEndpoint: coll.URL, Interval: 10 * time.Millisecond, ReportersCacheLen: 16,
		Features: []string{otelcfg.FeatureApplication}, Instrumentations: []string{instrumentations.InstrumentationHTTP},
	}
	reporter, err := ReportMetrics(&global.ContextInfo{
		Metrics:             internalMetrics,
		OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg},
	}, mcfg, &attributes.SelectorConfig{}, request.UnresolvedNames{}, exportMetrics, processEvents,
	)(t.Context())
	require.NoError(t, err)
	go reporter(t.Context())

	// send some dummy traces
	exportMetrics.Send([]request.Span{{Type: request.EventTypeHTTP}})

	var previousSum, previousCount int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we can't guarantee the number of calls at test time, but they must be at least 1
		previousSum, previousCount = internalMetrics.SumCount()
		assert.LessOrEqual(t, 1, previousSum)
		assert.LessOrEqual(t, 1, previousCount)
		// the count of metrics should be larger than the number of calls (1 call : n metrics)
		assert.Less(t, previousCount, previousSum)
		// no call should return error
		assert.Zero(t, internalMetrics.Errors())
	})

	// send another trace
	exportMetrics.Send([]request.Span{{Type: request.EventTypeHTTP}})

	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, cnt := internalMetrics.SumCount()
		assert.LessOrEqual(t, previousSum, sum)
		assert.LessOrEqual(t, previousCount, cnt)
		assert.Less(t, cnt, sum)
		// no call should return error
		assert.Zero(t, internalMetrics.Errors())
	})

	// collector starts failing, so errors should be received
	coll.CloseClientConnections()
	coll.Close()
	// Wait for the HTTP server to be stopped
	test.Eventually(t, timeout, func(t require.TestingT) {
		_, err := coll.Client().Get(coll.URL + "/foo")
		require.Error(t, err)
	})

	var previousErrCount int
	exportMetrics.Send([]request.Span{{Type: request.EventTypeHTTP}})
	test.Eventually(t, timeout, func(t require.TestingT) {
		previousSum, previousCount = internalMetrics.SumCount()
		// calls should start returning errors
		previousErrCount = internalMetrics.Errors()
		assert.NotZero(t, previousErrCount)
	})

	// after a while, metrics count should not increase but errors do
	exportMetrics.Send([]request.Span{{Type: request.EventTypeHTTP}})
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, cnt := internalMetrics.SumCount()
		assert.Equal(t, previousSum, sum)
		assert.Equal(t, previousCount, cnt)
		// calls should start returning errors
		assert.Less(t, previousErrCount, internalMetrics.Errors())
	})
}

type fakeInternalMetrics struct {
	imetrics.NoopReporter
	sum  atomic.Int32
	cnt  atomic.Int32
	errs atomic.Int32
}

type InstrTest struct {
	name      string
	instr     []string
	expected  []string
	extraColl int
}

func TestAppMetrics_ByInstrumentation(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()

	tests := []InstrTest{
		{
			name:      "all instrumentations",
			instr:     []string{instrumentations.InstrumentationALL},
			extraColl: 4,
			expected: []string{
				"http.server.request.duration",
				"http.client.request.duration",
				"rpc.server.duration",
				"rpc.client.duration",
				"db.client.operation.duration", // SQL client SELECT
				"db.client.operation.duration", // REDIS client SET
				"db.client.operation.duration", // Redis server GET (TODO is this a bug?)
				"db.client.operation.duration", // MongoDB client find
				"messaging.publish.duration",
				"messaging.process.duration",
			},
		},
		{
			name:      "http only",
			instr:     []string{instrumentations.InstrumentationHTTP},
			extraColl: 2,
			expected: []string{
				"http.server.request.duration",
				"http.client.request.duration",
			},
		},
		{
			name:      "grpc only",
			instr:     []string{instrumentations.InstrumentationGRPC},
			extraColl: 0,
			expected: []string{
				"rpc.server.duration",
				"rpc.client.duration",
			},
		},
		{
			name:      "redis only",
			instr:     []string{instrumentations.InstrumentationRedis},
			extraColl: 0,
			expected: []string{
				"db.client.operation.duration",
				"db.client.operation.duration",
			},
		},
		{
			name:      "sql only",
			instr:     []string{instrumentations.InstrumentationSQL},
			extraColl: 0,
			expected: []string{
				"db.client.operation.duration",
			},
		},
		{
			name:      "kafka only",
			instr:     []string{instrumentations.InstrumentationKafka},
			extraColl: 0,
			expected: []string{
				"messaging.publish.duration",
				"messaging.process.duration",
			},
		},
		{
			name:      "none",
			instr:     nil,
			extraColl: 0,
			expected:  []string{},
		},
		{
			name:      "sql and redis",
			instr:     []string{instrumentations.InstrumentationSQL, instrumentations.InstrumentationRedis},
			extraColl: 0,
			expected: []string{
				"db.client.operation.duration",
				"db.client.operation.duration",
				"db.client.operation.duration",
			},
		},
		{
			name:      "kafka and grpc",
			instr:     []string{instrumentations.InstrumentationGRPC, instrumentations.InstrumentationKafka},
			extraColl: 0,
			expected: []string{
				"rpc.server.duration",
				"rpc.client.duration",
				"messaging.publish.duration",
				"messaging.process.duration",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			otlp, err := collector.Start(ctx)
			require.NoError(t, err)

			metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
			processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
			otelExporter := makeMetricsReporter(ctx, t, tt.instr, []string{otelcfg.FeatureApplication}, otlp, metrics, processEvents).reportMetrics
			require.NoError(t, err)

			go otelExporter(ctx)

			/* Available event types (defined in span.go):
			EventTypeHTTP
			EventTypeGRPC
			EventTypeHTTPClient
			EventTypeGRPCClient
			EventTypeSQLClient
			EventTypeRedisClient
			EventTypeRedisServer
			EventTypeKafkaClient
			EventTypeRedisServer
			EventTypeKafkaServer
			*/
			// WHEN it receives metrics
			metrics.Send([]request.Span{
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTPClient, Path: "/bar", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPC, Path: "/foo", RequestStart: 100, End: 200},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPCClient, Path: "/bar", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeSQLClient, Path: "SELECT", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisClient, Method: "SET", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisServer, Method: "GET", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeMongoClient, Method: "find", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeKafkaClient, Method: "publish", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeKafkaServer, Method: "process", RequestStart: 150, End: 175},
			})

			// Read the exported metrics, add +extraColl for HTTP size metrics
			res := readNChan(t, otlp.Records(), len(tt.expected)+tt.extraColl, timeout)
			m := []collector.MetricRecord{}
			// skip over the byte size metrics
			for _, r := range res {
				if strings.HasSuffix(r.Name, ".duration") {
					m = append(m, r)
				}
			}
			assert.Len(t, m, len(tt.expected))

			for i := 0; i < len(tt.expected); i++ {
				assert.Equal(t, tt.expected[i], m[i].Name)
			}

			otelcfg.RestoreEnvAfterExecution()
		})
	}
}

func TestAppMetrics_ResourceAttributes(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()

	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=production,source=upstream.beyla")

	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	otelExporter := makeMetricsReporter(ctx, t, []string{instrumentations.InstrumentationHTTP}, []string{otelcfg.FeatureApplication}, otlp, metrics, processEvents).reportMetrics
	go otelExporter(ctx)

	metrics.Send([]request.Span{
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
	})

	res := readNChan(t, otlp.Records(), 1, timeout)
	assert.Len(t, res, 1)
	attributes := res[0].ResourceAttributes
	assert.Equal(t, "production", attributes["deployment.environment"])
	assert.Equal(t, "upstream.beyla", attributes["source"])
}

func TestMetricsDiscarded(t *testing.T) {
	mc := otelcfg.MetricsConfig{
		Features: []string{otelcfg.FeatureApplication},
	}
	mr := MetricsReporter{
		cfg: &mc,
	}

	svcNoExport := svc.Attrs{}

	svcExportMetrics := svc.Attrs{}
	svcExportMetrics.SetExportsOTelMetrics()

	svcExportTraces := svc.Attrs{}
	svcExportTraces.SetExportsOTelTraces()

	tests := []struct {
		name      string
		span      request.Span
		discarded bool
	}{
		{
			name:      "Foo span is not filtered",
			span:      request.Span{Service: svcNoExport, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			discarded: false,
		},
		{
			name:      "/v1/metrics span is filtered",
			span:      request.Span{Service: svcExportMetrics, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/metrics", RequestStart: 100, End: 200},
			discarded: true,
		},
		{
			name:      "/v1/traces span is not filtered",
			span:      request.Span{Service: svcExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200},
			discarded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.discarded, !otelMetricsAccepted(&tt.span, &mr), tt.name)
		})
	}
}

func TestSpanMetricsDiscarded(t *testing.T) {
	mc := otelcfg.MetricsConfig{
		Features: []string{otelcfg.FeatureSpan},
	}
	mr := MetricsReporter{
		cfg: &mc,
	}

	svcNoExport := svc.Attrs{}

	svcExportMetrics := svc.Attrs{}
	svcExportMetrics.SetExportsOTelMetrics()

	svcExportSpanMetrics := svc.Attrs{}
	svcExportSpanMetrics.SetExportsOTelMetricsSpan()

	tests := []struct {
		name      string
		span      request.Span
		discarded bool
	}{
		{
			name:      "Foo span is not filtered",
			span:      request.Span{Service: svcNoExport, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			discarded: false,
		},
		{
			name:      "/v1/metrics span is not filtered",
			span:      request.Span{Service: svcExportMetrics, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/metrics", RequestStart: 100, End: 200},
			discarded: false,
		},
		{
			name:      "/v1/traces span is filtered",
			span:      request.Span{Service: svcExportSpanMetrics, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200},
			discarded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.discarded, !otelSpanMetricsAccepted(&tt.span, &mr), tt.name)
		})
	}
}

func TestSpanMetricsDiscardedGraph(t *testing.T) {
	mc := otelcfg.MetricsConfig{
		Features: []string{otelcfg.FeatureGraph},
	}
	mr := MetricsReporter{
		cfg: &mc,
	}

	svcNoExport := svc.Attrs{}

	svcExportMetrics := svc.Attrs{}
	svcExportMetrics.SetExportsOTelMetrics()

	svcExportSpanMetrics := svc.Attrs{}
	svcExportSpanMetrics.SetExportsOTelMetricsSpan()

	tests := []struct {
		name      string
		span      request.Span
		discarded bool
	}{
		{
			name:      "Foo span is not filtered",
			span:      request.Span{Service: svcNoExport, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			discarded: false,
		},
		{
			name:      "/v1/metrics span is not filtered",
			span:      request.Span{Service: svcExportMetrics, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/metrics", RequestStart: 100, End: 200},
			discarded: false,
		},
		{
			name:      "/v1/traces span is filtered",
			span:      request.Span{Service: svcExportSpanMetrics, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200},
			discarded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.discarded, !otelSpanMetricsAccepted(&tt.span, &mr), tt.name)
		})
	}
}

func TestProcessPIDEvents(t *testing.T) {
	mc := otelcfg.MetricsConfig{
		Features: []string{otelcfg.FeatureApplication},
	}
	mr := MetricsReporter{
		cfg:        &mc,
		pidTracker: NewPidServiceTracker(),
	}

	svcA := svc.Attrs{
		UID: svc.UID{Name: "A", Instance: "A"},
	}
	svcB := svc.Attrs{
		UID: svc.UID{Name: "B", Instance: "B"},
	}

	mr.setupPIDToServiceRelationship(1, svcA.UID)
	mr.setupPIDToServiceRelationship(2, svcA.UID)
	mr.setupPIDToServiceRelationship(3, svcB.UID)
	mr.setupPIDToServiceRelationship(4, svcB.UID)

	deleted, uid := mr.disassociatePIDFromService(1)
	assert.Equal(t, false, deleted)
	assert.Equal(t, svc.UID{}, uid)

	deleted, uid = mr.disassociatePIDFromService(1)
	assert.Equal(t, false, deleted)
	assert.Equal(t, svc.UID{}, uid)

	deleted, uid = mr.disassociatePIDFromService(2)
	assert.Equal(t, true, deleted)
	assert.Equal(t, svcA.UID, uid)

	deleted, uid = mr.disassociatePIDFromService(3)
	assert.Equal(t, false, deleted)
	assert.Equal(t, svc.UID{}, uid)

	deleted, uid = mr.disassociatePIDFromService(4)
	assert.Equal(t, true, deleted)
	assert.Equal(t, svcB.UID, uid)
}

func (f *fakeInternalMetrics) OTELMetricExport(length int) {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	f.cnt.Add(1)
	f.sum.Add(int32(length))
}

func (f *fakeInternalMetrics) OTELMetricExportError(_ error) {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	f.errs.Add(1)
}

func (f *fakeInternalMetrics) Errors() int {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	return int(f.errs.Load())
}

func (f *fakeInternalMetrics) SumCount() (sum, count int) {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	return int(f.sum.Load()), int(f.cnt.Load())
}

func readNChan(t require.TestingT, inCh <-chan collector.MetricRecord, numRecords int, timeout time.Duration) []collector.MetricRecord {
	records := []collector.MetricRecord{}
	for range numRecords {
		select {
		case item := <-inCh:
			records = append(records, item)
		case <-time.After(timeout):
			require.Failf(t, "timeout while waiting for event in input channel", "timeout: %s", timeout)
			return records
		}
	}
	return records
}

func makeMetricsReporter(
	ctx context.Context, t *testing.T, instrumentations []string, features []string, otlp *collector.TestCollector,
	input *msg.Queue[[]request.Span], processEvents *msg.Queue[exec.ProcessEvent],
) *MetricsReporter {
	mcfg := &otelcfg.MetricsConfig{
		Interval:          50 * time.Millisecond,
		CommonEndpoint:    otlp.ServerEndpoint,
		MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
		Features:          features,
		TTL:               30 * time.Minute,
		ReportersCacheLen: 100,
		Instrumentations:  instrumentations,
	}
	mr, err := newMetricsReporter(
		ctx,
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.HTTPServerDuration.Section: attributes.InclusionLists{
					Include: []string{"url.path"},
				},
			},
		},
		request.UnresolvedNames{},
		input,
		processEvents)

	require.NoError(t, err)
	return mr
}

func TestAppMetrics_TracesHostInfo(t *testing.T) {
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	metrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	mr := makeMetricsReporter(ctx, t, []string{instrumentations.InstrumentationHTTP}, []string{otelcfg.FeatureApplication, otelcfg.FeatureApplicationHost}, otlp, metrics, processEvents)
	otelExporter := mr.reportMetrics
	go otelExporter(ctx)

	assert.Len(t, otlp.Records(), 0, "metric reported before the first span is sent")

	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: &exec.FileInfo{
			Service: svc.Attrs{
				UID: svc.UID{Instance: "foo"},
			},
		},
	})

	metrics.Send([]request.Span{
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
	})

	test.Eventually(t, timeout, func(t require.TestingT) {
		assert.NotEmpty(t, mr.hostInfo.entries.All(),
			"traces_host_info metric has not been created yet")
	})

	// Check expiration logic
	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventTerminated,
		File: &exec.FileInfo{
			Service: svc.Attrs{
				UID: svc.UID{Instance: "foo"},
			},
		},
	})

	now.Advance(50 * time.Minute)

	test.Eventually(t, timeout, func(t require.TestingT) {
		assert.Empty(t, mr.hostInfo.entries.All(),
			"traces_host_info metric has not expired yet") // The entry should be expired
	})
}

func TestMetricResourceAttributes(t *testing.T) {
	// Test different filtering scenarios
	testCases := []struct {
		name            string
		service         *svc.Attrs
		attributeSelect attributes.Selection
		expectedAttrs   []string
		unexpectedAttrs []string
	}{
		{
			name: "No filtering configuration",
			service: &svc.Attrs{
				UID: svc.UID{
					Name:      "test-service",
					Instance:  "test-instance",
					Namespace: "test-namespace",
				},
				HostName:    "test-host",
				SDKLanguage: svc.InstrumentableGolang,
				Metadata: map[attr.Name]string{
					attr.K8sNamespaceName:  "k8s-namespace",
					attr.K8sPodName:        "pod-name",
					attr.K8sDeploymentName: "deployment-name",
					attr.K8sClusterName:    "cluster-name",
				},
			},
			attributeSelect: attributes.Selection{},
			expectedAttrs: []string{
				"service.name",
				"service.instance.id",
				"service.namespace",
				"telemetry.sdk.language",
				"telemetry.sdk.name",
				"host.id",
				"k8s.namespace.name",
				"k8s.pod.name",
				"k8s.deployment.name",
				"k8s.cluster.name",
				"source",
			},
			unexpectedAttrs: []string{},
		},
		{
			name: "Filter out host attributes",
			service: &svc.Attrs{
				UID: svc.UID{
					Name:      "test-service",
					Instance:  "test-instance",
					Namespace: "test-namespace",
				},
				HostName:    "test-host",
				SDKLanguage: svc.InstrumentableGolang,
				Metadata: map[attr.Name]string{
					attr.K8sNamespaceName:  "k8s-namespace",
					attr.K8sPodName:        "pod-name",
					attr.K8sDeploymentName: "deployment-name",
					attr.K8sClusterName:    "cluster-name",
				},
			},
			attributeSelect: attributes.Selection{
				"http.server.request.duration": attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"host.*"},
				},
			},
			expectedAttrs: []string{
				"service.name",
				"service.instance.id",
				"service.namespace",
				"telemetry.sdk.language",
				"telemetry.sdk.name",
				"k8s.namespace.name",
				"k8s.pod.name",
				"k8s.deployment.name",
				"k8s.cluster.name",
				"source",
			},
			unexpectedAttrs: []string{
				"host.id",
			},
		},
		{
			name: "Filter out k8s attributes",
			service: &svc.Attrs{
				UID: svc.UID{
					Name:      "test-service",
					Instance:  "test-instance",
					Namespace: "test-namespace",
				},
				HostName:    "test-host",
				SDKLanguage: svc.InstrumentableGolang,
				Metadata: map[attr.Name]string{
					attr.K8sNamespaceName:  "k8s-namespace",
					attr.K8sPodName:        "pod-name",
					attr.K8sDeploymentName: "deployment-name",
					attr.K8sClusterName:    "cluster-name",
				},
			},
			attributeSelect: attributes.Selection{
				"http.server.request.duration": attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"k8s.*"},
				},
			},
			expectedAttrs: []string{
				"service.name",
				"service.instance.id",
				"service.namespace",
				"telemetry.sdk.language",
				"telemetry.sdk.name",
				"host.id",
				"source",
			},
			unexpectedAttrs: []string{
				"k8s.namespace.name",
				"k8s.pod.name",
				"k8s.deployment.name",
				"k8s.cluster.name",
			},
		},
		{
			name: "Only include specific attributes",
			service: &svc.Attrs{
				UID: svc.UID{
					Name:      "test-service",
					Instance:  "test-instance",
					Namespace: "test-namespace",
				},
				HostName:    "test-host",
				SDKLanguage: svc.InstrumentableGolang,
				Metadata: map[attr.Name]string{
					attr.K8sNamespaceName:  "k8s-namespace",
					attr.K8sPodName:        "pod-name",
					attr.K8sDeploymentName: "deployment-name",
					attr.K8sClusterName:    "cluster-name",
				},
			},
			attributeSelect: attributes.Selection{
				"http.server.request.duration": attributes.InclusionLists{
					Include: []string{"service.*", "telemetry.*"},
					Exclude: []string{},
				},
			},
			expectedAttrs: []string{
				"service.name",
				"service.instance.id",
				"service.namespace",
				"telemetry.sdk.language",
				"telemetry.sdk.name",
				"source",
			},
			unexpectedAttrs: []string{
				"host.id",
				"k8s.namespace.name",
				"k8s.pod.name",
				"k8s.deployment.name",
				"k8s.cluster.name",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mr := &MetricsReporter{
				hostID:              "test-host-id",
				userAttribSelection: tc.attributeSelect,
			}

			attrSet := mr.tracesResourceAttributes(tc.service)

			attrs := attrSet.ToSlice()
			attrMap := make(map[string]string)

			t.Logf("Attributes in test %s:", tc.name)
			for _, a := range attrs {
				keyStr := string(a.Key)
				t.Logf("   - %s = %s", keyStr, a.Value.Emit())
				attrMap[keyStr] = a.Value.Emit()
			}

			for _, attrName := range tc.expectedAttrs {
				_, exists := attrMap[attrName]
				assert.True(t, exists, "Expected attribute %s not found. Available keys: %v", attrName, getKeys(attrMap))
			}

			for _, attrName := range tc.unexpectedAttrs {
				_, exists := attrMap[attrName]
				assert.False(t, exists, "Unexpected attribute %s found", attrName)
			}
		})
	}
}

func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestClientSpanToUninstrumentedService(t *testing.T) {
	tracker := NewPidServiceTracker()
	uid := svc.UID{Name: "foo", Namespace: "bar"}
	tracker.AddPID(1, uid)

	spanInstrumented := &request.Span{
		HostName:       "foo",
		OtherNamespace: "bar",
	}
	if ClientSpanToUninstrumentedService(&tracker, spanInstrumented) {
		t.Errorf("Expected false for instrumented service, got true")
	}

	spanUninstrumented := &request.Span{
		HostName:       "baz",
		OtherNamespace: "qux",
	}
	if !ClientSpanToUninstrumentedService(&tracker, spanUninstrumented) {
		t.Errorf("Expected true for uninstrumented service, got false")
	}

	spanNoHost := &request.Span{
		HostName:       "",
		OtherNamespace: "bar",
	}
	if ClientSpanToUninstrumentedService(&tracker, spanNoHost) {
		t.Errorf("Expected false for span with no HostName, got true")
	}
}

type mockEventMetrics struct {
	createCalls []*TargetMetrics
	deleteCalls []*TargetMetrics
}

func newMockEventMetrics() *mockEventMetrics {
	return &mockEventMetrics{
		createCalls: make([]*TargetMetrics, 0),
		deleteCalls: make([]*TargetMetrics, 0),
	}
}

func (m *mockEventMetrics) createEventMetrics(targetMetrics *TargetMetrics) {
	m.createCalls = append(m.createCalls, targetMetrics)
}

func (m *mockEventMetrics) deleteEventMetrics(targetMetrics *TargetMetrics) {
	m.deleteCalls = append(m.deleteCalls, targetMetrics)
}

func TestHandleProcessEventCreated(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*MetricsReporter, *mockEventMetrics)
		event          exec.ProcessEvent
		expectedCreate []svc.Attrs
		expectedDelete []svc.Attrs
		expectedMap    map[svc.UID]svc.Attrs
	}{
		{
			name: "new service - fresh start",
			setup: func(r *MetricsReporter, m *mockEventMetrics) {
				// No setup needed for fresh start
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "test-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "test-host",
					},
				},
			},
			expectedCreate: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
			expectedDelete: nil,
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
		},
		{
			name: "same service UID with updated attributes",
			setup: func(r *MetricsReporter, m *mockEventMetrics) {
				// Pre-populate service map with existing service
				uid := svc.UID{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.targetMetrics[uid] = attrsToTargetMetrics(r, &svc.Attrs{
					UID:      uid,
					HostName: "old-host",
				})
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "test-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "new-host",
					},
				},
			},
			expectedCreate: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "new-host",
				},
			},
			expectedDelete: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "old-host",
				},
			},
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "new-host",
				},
			},
		},
		{
			name: "PID changing service (stale UID with existing attributes)",
			setup: func(r *MetricsReporter, m *mockEventMetrics) {
				// Setup: PID 1234 is already tracked with stale UID
				staleUID := svc.UID{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.pidTracker.AddPID(1234, staleUID)

				// Add stale service to service map
				r.targetMetrics[staleUID] = attrsToTargetMetrics(r, &svc.Attrs{
					UID:      staleUID,
					HostName: "test-host",
				})
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "new-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "test-host",
					},
				},
			},
			expectedCreate: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "new-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
			expectedDelete: []svc.Attrs{
				{
					UID: svc.UID{
						Name:      "old-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "new-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "new-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
		},
		{
			name: "PID changing service (stale UID without existing attributes)",
			setup: func(r *MetricsReporter, m *mockEventMetrics) {
				// Setup: PID 1234 is already tracked with stale UID, but no service map entry
				staleUID := svc.UID{
					Name:      "old-service",
					Namespace: "default",
					Instance:  "instance-1",
				}
				r.pidTracker.AddPID(1234, staleUID)
				// Note: deliberately NOT adding to serviceMap to test this edge case
			},
			event: exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{
					Pid: 1234,
					Service: svc.Attrs{
						UID: svc.UID{
							Name:      "new-service",
							Namespace: "default",
							Instance:  "instance-1",
						},
						HostName: "test-host",
					},
				},
			},
			expectedCreate: nil,
			expectedDelete: nil,
			expectedMap: map[svc.UID]svc.Attrs{
				{
					Name:      "new-service",
					Namespace: "default",
					Instance:  "instance-1",
				}: {
					UID: svc.UID{
						Name:      "new-service",
						Namespace: "default",
						Instance:  "instance-1",
					},
					HostName: "test-host",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEventsStore := mockEventMetrics{}

			// Create a minimal metricsReporter with mocks
			reporter := &MetricsReporter{
				cfg:                &otelcfg.MetricsConfig{},
				log:                slog.Default(),
				targetMetrics:      make(map[svc.UID]*TargetMetrics),
				pidTracker:         NewPidServiceTracker(),
				createEventMetrics: mockEventsStore.createEventMetrics,
				deleteEventMetrics: mockEventsStore.deleteEventMetrics,
			}

			// Setup any initial state
			tt.setup(reporter, &mockEventsStore)

			// Execute the function under test
			reporter.onProcessEvent(&tt.event)

			// Verify create calls
			for i, cc := range tt.expectedCreate {
				c := attrsToTargetMetrics(reporter, &cc)
				resourcesMatch(t, c, mockEventsStore.createCalls[i])
			}

			// Verify delete calls
			for i, cc := range tt.expectedDelete {
				c := attrsToTargetMetrics(reporter, &cc)
				resourcesMatch(t, c, mockEventsStore.deleteCalls[i])
			}

			tm := map[svc.UID]*TargetMetrics{}

			for uid, attrs := range tt.expectedMap {
				tm[uid] = attrsToTargetMetrics(reporter, &attrs)
			}

			// Verify service map state
			assert.Equal(t, tm, reporter.targetMetrics,
				"Service map should match expected state")
		})
	}
}

func TestHandleProcessEventCreated_EdgeCases(t *testing.T) {
	t.Run("multiple PIDs for same service", func(t *testing.T) {
		mockEventsStore := newMockEventMetrics()

		reporter := &MetricsReporter{
			cfg:                &otelcfg.MetricsConfig{},
			log:                slog.Default(),
			targetMetrics:      make(map[svc.UID]*TargetMetrics),
			pidTracker:         NewPidServiceTracker(),
			createEventMetrics: mockEventsStore.createEventMetrics,
			deleteEventMetrics: mockEventsStore.deleteEventMetrics,
		}

		uid := svc.UID{Name: "multi-pid-service", Namespace: "default", Instance: "instance-1"}
		service := svc.Attrs{UID: uid, HostName: "test-host"}

		// Add first PID
		event1 := exec.ProcessEvent{
			Type: exec.ProcessEventCreated,
			File: &exec.FileInfo{Pid: 1111, Service: service},
		}
		reporter.onProcessEvent(&event1)

		// Add second PID for same service
		event2 := exec.ProcessEvent{
			Type: exec.ProcessEventCreated,
			File: &exec.FileInfo{Pid: 2222, Service: service},
		}
		reporter.onProcessEvent(&event2)

		// Service should only be created once initially, then updated once for the same UID
		assert.Len(t, mockEventsStore.createCalls, 2) // One for each PID event
		assert.Len(t, mockEventsStore.deleteCalls, 1) // One delete when second event updates existing service
	})

	t.Run("concurrent service updates", func(t *testing.T) {
		mockEventsStore := newMockEventMetrics()

		reporter := &MetricsReporter{
			cfg:                &otelcfg.MetricsConfig{},
			log:                slog.Default(),
			targetMetrics:      make(map[svc.UID]*TargetMetrics),
			pidTracker:         NewPidServiceTracker(),
			createEventMetrics: mockEventsStore.createEventMetrics,
			deleteEventMetrics: mockEventsStore.deleteEventMetrics,
		}

		uid := svc.UID{Name: "concurrent-service", Namespace: "default", Instance: "instance-1"}

		// Simulate rapid updates to same service with different metadata
		for i := range 5 {
			service := svc.Attrs{
				UID:      uid,
				HostName: fmt.Sprintf("host-%d", i),
			}

			event := exec.ProcessEvent{
				Type: exec.ProcessEventCreated,
				File: &exec.FileInfo{Pid: int32(1000 + i), Service: service},
			}
			reporter.onProcessEvent(&event)
		}

		hostKey := attribute.Key(attr.HostName)
		// Should end up with latest service attributes
		finalService := reporter.targetMetrics[uid]
		hostName, ok := finalService.resourceAttributes.Value(hostKey)
		assert.True(t, ok)
		assert.Equal(t, "host-4", hostName.AsString())

		// Should have created 5 times and deleted 4 times (each update after first deletes previous)
		assert.Len(t, mockEventsStore.createCalls, 5)
		assert.Len(t, mockEventsStore.deleteCalls, 4)
	})
}

func attrsToTargetMetrics(mr *MetricsReporter, attrs *svc.Attrs) *TargetMetrics {
	targetMetrics := &TargetMetrics{}

	targetMetrics.resourceAttributes = attribute.NewSet(mr.resourceAttrsForService(attrs)...)

	targetMetrics.tracesResourceAttributes = *attribute.EmptySet()

	return targetMetrics
}

func resourcesMatch(t *testing.T, one *TargetMetrics, two *TargetMetrics) {
	assert.Equal(t, one.resourceAttributes.Len(), two.resourceAttributes.Len())

	for i := 0; i < one.resourceAttributes.Len(); i++ {
		a, ok := one.resourceAttributes.Get(i)
		assert.True(t, ok)

		other, ok := two.resourceAttributes.Value(a.Key)
		assert.True(t, ok)
		assert.Equal(t, a.Value.AsString(), other.AsString())
	}
}
