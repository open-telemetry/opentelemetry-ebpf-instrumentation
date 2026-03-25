// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

func TestServiceNameTemplate(t *testing.T) {
	cfg := &obi.Config{
		Attributes: obi.Attributes{
			Kubernetes: transform.KubernetesDecorator{
				ServiceNameTemplate: "{{asdf}}",
			},
		},
	}

	temp, err := buildServiceNameTemplate(cfg)
	assert.Nil(t, temp)
	if assert.Error(t, err) {
		assert.Equal(t, `unable to parse service name template: template: serviceNameTemplate:1: function "asdf" not defined`, err.Error())
	}

	cfg.Attributes.Kubernetes.ServiceNameTemplate = `{{- if eq .Meta.Pod nil }}{{.Meta.Name}}{{ else }}{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}{{ end -}}`
	temp, err = buildServiceNameTemplate(cfg)

	require.NoError(t, err)
	assert.NotNil(t, temp)

	cfg.Attributes.Kubernetes.ServiceNameTemplate = ""
	temp, err = buildServiceNameTemplate(cfg)
	require.NoError(t, err)
	assert.Nil(t, temp)
}

// TestRun_WithDynamicPIDSelector verifies that when the caller passes a selector via
// WithDynamicPIDSelector, Run uses it and the caller can add/remove PIDs on it directly—
// no callback or reference to the instrumenter is needed.
func TestRun_WithDynamicPIDSelector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sel := discover.NewDynamicPIDSelector()
	cfg := &obi.Config{
		ChannelBufferLen: 1,
		Traces:           otelcfg.TracesConfig{TracesEndpoint: "http://localhost:0"},
		Discovery: services.DiscoveryConfig{
			Instrument: services.GlobDefinitionCriteria{
				services.GlobAttributes{Name: "test-svc", OpenPorts: services.IntEnum{Ranges: []services.IntRange{{Start: 8080}}}},
			},
		},
	}
	require.True(t, cfg.Enabled(obi.FeatureAppO11y), "test config must enable App O11y")

	opts := []Option{WithDynamicPIDSelector(sel)}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, opts...) }()

	time.Sleep(2 * time.Second)
	sel.AddPIDs(42, 100)
	sel.AddPIDs(42, 200)
	sel.RemovePIDs(42)
	sel.RemovePIDs(999)
	pids, ok := sel.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{100, 200}, pids)
	cancel()
	<-done
}
