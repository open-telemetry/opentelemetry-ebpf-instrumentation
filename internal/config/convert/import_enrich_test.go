// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestV2ToRuntimeEnrichAttributesAndKubernetesRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledTrue
	cfg.Attributes.Kubernetes.ClusterName = "cluster-a"
	cfg.Attributes.Kubernetes.KubeconfigPath = "/etc/kube/config"
	cfg.Attributes.Kubernetes.InformersSyncTimeout = 42 * time.Second
	cfg.Attributes.Kubernetes.ReconnectInitialInterval = 43 * time.Second
	cfg.Attributes.Kubernetes.InformersResyncPeriod = 0
	cfg.Attributes.Kubernetes.DropExternal = true
	cfg.Attributes.Kubernetes.DisableInformers = []string{"node", "service"}
	cfg.Attributes.Kubernetes.MetaCacheAddress = "kube-cache:8999"
	cfg.Attributes.Kubernetes.MetaRestrictLocalNode = true
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName = "app.kubernetes.io/name"
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace = "app.kubernetes.io/part-of"
	cfg.Attributes.Kubernetes.ResourceLabels = map[string][]string{
		"service.name":    {"app"},
		"service.version": {"version", "release"},
	}
	cfg.Attributes.Kubernetes.ServiceNameTemplate = "{{ .Meta.Name }}"
	cfg.Attributes.MetadataRetry = meta.RetryConfig{
		Timeout:       0,
		StartInterval: 46 * time.Millisecond,
		MaxInterval:   47 * time.Second,
	}
	cfg.Attributes.Select = attributes.Selection{
		"traces": attributes.InclusionLists{
			Include: []string{"http.route"},
			Exclude: []string{"url.full"},
		},
		"http.server.duration": attributes.InclusionLists{
			Include: []string{"k8s.*"},
			Exclude: []string{"k8s.pod.uid"},
		},
	}
	cfg.Attributes.Select.Normalize()
	cfg.Attributes.ExtraGroupAttributes = obi.ExtraGroupAttributesMap{
		"k8s_app_meta": []attr.Name{attr.K8sPodName, attr.K8sNamespaceName},
	}

	_, ext := RuntimeToV2(&cfg)
	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, cfg.Attributes.Kubernetes, got.Attributes.Kubernetes)
	require.Equal(t, cfg.Attributes.MetadataRetry, got.Attributes.MetadataRetry)
	require.Equal(t, cfg.Attributes.Select, got.Attributes.Select)
	require.Equal(t, cfg.Attributes.ExtraGroupAttributes, got.Attributes.ExtraGroupAttributes)
}

func TestV2ToRuntimeKubernetesMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode schema.KubernetesMode
		want kubeflags.EnableFlag
	}{
		{
			name: "enabled",
			mode: schema.KubernetesModeEnabled,
			want: kubeflags.EnabledTrue,
		},
		{
			name: "disabled",
			mode: schema.KubernetesModeDisabled,
			want: kubeflags.EnabledFalse,
		},
		{
			name: "autodetect",
			mode: schema.KubernetesModeAutodetect,
			want: kubeflags.EnabledAutodetect,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ext := &schema.Extension{
				Version: schema.SupportedVersion,
				Enrich: &schema.Enrich{
					Enrichers: schema.Enrichers{
						Kubernetes: schema.KubernetesEnricher{
							Mode: test.mode,
						},
					},
				},
			}

			got, err := V2ToRuntime(ext)
			require.NoError(t, err)
			require.Equal(t, test.want, got.Attributes.Kubernetes.Enable)
		})
	}
}

func TestV2ToRuntimeEmptyEnrichPreservesDefaults(t *testing.T) {
	t.Parallel()

	ext := &schema.Extension{
		Version: schema.SupportedVersion,
		Enrich: &schema.Enrich{
			Enrichers:  schema.Enrichers{},
			Attributes: schema.EnrichmentAttributes{},
		},
	}

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.Attributes.Kubernetes, got.Attributes.Kubernetes)
	require.Equal(t, obi.DefaultConfig.Attributes.MetadataRetry, got.Attributes.MetadataRetry)
	require.Equal(t, obi.DefaultConfig.Attributes.Select, got.Attributes.Select)
	require.Equal(t, obi.DefaultConfig.Attributes.ExtraGroupAttributes, got.Attributes.ExtraGroupAttributes)
}
