package instrumenter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/transform"

	"github.com/stretchr/testify/assert"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/obi"
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
