// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/internal/ecs"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type ecsProcessClient struct {
	tasks []types.Task
}

func (c *ecsProcessClient) ListTasks(context.Context, *awsecs.ListTasksInput, ...func(*awsecs.Options)) (*awsecs.ListTasksOutput, error) {
	return &awsecs.ListTasksOutput{TaskArns: []string{"task"}}, nil
}

func (c *ecsProcessClient) DescribeTasks(context.Context, *awsecs.DescribeTasksInput, ...func(*awsecs.Options)) (*awsecs.DescribeTasksOutput, error) {
	return &awsecs.DescribeTasksOutput{Tasks: c.tasks}, nil
}

func TestECSProcessDecorator(t *testing.T) {
	id := strings.Repeat("a", 64)
	client := &ecsProcessClient{}
	inventory := ecs.NewInventory(client, "cluster")
	input := make(chan exec.ProcessEvent)
	output := msg.NewQueue[exec.ProcessEvent]()
	result := output.Subscribe(msg.SubscriberName("test"))
	d := ecsProcessDecorator{
		inventory: inventory, input: input, output: output,
		processes: map[app.PID]*ecsProcess{},
		containerInfo: func(pid app.PID) (container.Info, error) {
			if pid == 3 {
				return container.Info{}, errors.New("process unavailable")
			}
			return container.Info{ContainerID: id}, nil
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	checkTargetInfo := ecsTargetInfoExporters(ctx, t, output)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("process decorator did not stop")
		}
	})
	read := func() exec.ProcessEvent {
		t.Helper()
		select {
		case event := <-result:
			return event
		case <-time.After(5 * time.Second):
			t.Fatal("process decorator did not forward event")
			return exec.ProcessEvent{}
		}
	}
	send := func(event exec.ProcessEvent) {
		t.Helper()
		select {
		case input <- event:
		case <-time.After(5 * time.Second):
			t.Fatal("process decorator did not accept event")
		}
		read()
	}
	newFile := func(pid app.PID, auto bool) *exec.FileInfo {
		service := svc.Attrs{UID: svc.UID{Name: "container-name", Namespace: "ns", Instance: "instance"}}
		service.Features = export.FeatureApplicationRED
		if auto {
			service.SetAutoName()
		}
		return exec.New(exec.Init{Pid: pid, Service: service})
	}
	file := newFile(1, true)
	send(exec.ProcessEvent{File: file, Type: exec.ProcessEventCreated})
	assert.Equal(t, "container-name", file.ServiceAttrs().UID.Name)
	checkTargetInfo("container-name", "checkout")

	// Metadata arriving after discovery updates the same process without traffic.
	client.tasks = []types.Task{{Group: aws.String("service:checkout"), Containers: []types.Container{{RuntimeId: aws.String(id)}}}}
	require.NoError(t, inventory.Refresh(ctx))
	updated := read()
	assert.Same(t, file, updated.File)
	assert.Equal(t, exec.ProcessEventCreated, updated.Type)
	assert.Equal(t, svc.UID{Name: "checkout", Namespace: "ns", Instance: "instance"}, file.ServiceAttrs().UID)
	checkTargetInfo("checkout", "container-name")
	span := request.Span{Type: request.EventTypeHTTP, Host: "127.0.0.1", Service: file.ServiceAttrs()}
	// Docker span decoration may assign the generated name again.
	span.Service.UID.Name = "container-name"
	resolver := NameResolver{ecs: inventory, sources: ResolverECS, logger: nrlog()}
	resolver.resolveNames(&span)
	assert.Equal(t, "checkout", span.Service.UID.Name)
	assert.Equal(t, id, span.Service.RuntimeContainerID)

	explicit := newFile(2, false)
	send(exec.ProcessEvent{File: explicit, Type: exec.ProcessEventCreated})
	assert.Equal(t, "container-name", explicit.ServiceAttrs().UID.Name)
	unavailable := newFile(3, true)
	send(exec.ProcessEvent{File: unavailable, Type: exec.ProcessEventCreated})
	assert.Equal(t, "container-name", unavailable.ServiceAttrs().UID.Name)

	// Repeated discovery keeps the original fallback even after ECS decoration.
	send(exec.ProcessEvent{File: file, Type: exec.ProcessEventCreated})
	client.tasks = nil
	require.NoError(t, inventory.Refresh(ctx))
	assert.Same(t, file, read().File)
	assert.Equal(t, "container-name", file.ServiceAttrs().UID.Name)

	client.tasks = []types.Task{{Group: aws.String("service:payments"), Containers: []types.Container{{RuntimeId: aws.String(id)}}}}
	require.NoError(t, inventory.Refresh(ctx))
	assert.Same(t, file, read().File)
	assert.Equal(t, "payments", file.ServiceAttrs().UID.Name)
	send(exec.ProcessEvent{File: file, Type: exec.ProcessEventTerminated})
	client.tasks = nil
	require.NoError(t, inventory.Refresh(ctx))
	// A subsequent event acts as a barrier through the same decorator loop.
	send(exec.ProcessEvent{File: explicit, Type: exec.ProcessEventCreated})
	close(input)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("process decorator did not stop after input closure")
	}
	assert.NotContains(t, d.processes, app.PID(1))
	assert.Equal(t, "payments", file.ServiceAttrs().UID.Name)
	assert.Equal(t, "container-name", explicit.ServiceAttrs().UID.Name)
}

func ecsTargetInfoExporters(ctx context.Context, t *testing.T, events *msg.Queue[exec.ProcessEvent]) func(string, string) {
	t.Helper()
	registry := prometheus.NewRegistry()
	spans := msg.NewQueue[[]request.Span]()
	features := &perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRED}
	selector := &attributes.SelectorConfig{}
	promRun, err := prom.PrometheusEndpoint(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&prom.PrometheusConfig{
			Registry: registry, TTL: time.Minute, SpanMetricsServiceCacheSize: 10,
			Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
		}, features, selector, request.UnresolvedNames{}, spans, events, nil,
	)(ctx)
	require.NoError(t, err)
	go promRun(ctx)
	otlp, err := collector.Start(ctx)
	require.NoError(t, err)
	metricCfg := &otelcfg.MetricsConfig{
		CommonEndpoint: otlp.ServerEndpoint, MetricsProtocol: otelcfg.ProtocolHTTPProtobuf,
		Interval: 10 * time.Millisecond, TTL: time.Minute, ReportersCacheLen: 10,
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}
	otelRun, err := otel.ReportMetrics(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: metricCfg}},
		metricCfg, features, selector, request.UnresolvedNames{}, spans, events,
	)(ctx)
	require.NoError(t, err)
	go otelRun(ctx)
	return func(expected, absent string) {
		t.Helper()
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			families, err := registry.Gather()
			require.NoError(ct, err)
			var names []string
			for _, family := range families {
				if family.GetName() == "target_info" {
					for _, metric := range family.Metric {
						for _, label := range metric.Label {
							if label.GetName() == "service_name" {
								names = append(names, label.GetValue())
							}
						}
					}
				}
			}
			assert.Contains(ct, names, expected)
			assert.NotContains(ct, names, absent)
		}, 5*time.Second, 10*time.Millisecond)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case record := <-otlp.Records():
				if record.Name == "target.info" && record.Attributes["service.name"] == expected {
					assert.EqualValues(t, 1, record.IntVal)
					return
				}
			case <-timer.C:
				t.Fatalf("OTLP target.info did not report service %q", expected)
			}
		}
	}
}
