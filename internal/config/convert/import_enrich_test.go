// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube/kubecache"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
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
	cfg.Attributes.Kubernetes.MetaCacheGRPC = kubecache.GRPCSecurity{
		Mode: "mtls", ServerName: "kube-cache", CAFile: "/etc/obi/ca.pem",
		CertFile: "/etc/obi/client.pem", KeyFile: "/etc/obi/client.key",
	}
	cfg.Attributes.Kubernetes.MetaRestrictLocalNode = true
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName = "app.kubernetes.io/name"
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace = "app.kubernetes.io/part-of"
	cfg.Attributes.Kubernetes.ResourceLabels = map[string][]string{
		"service.name":    {"app"},
		"service.version": {"version", "release"},
	}
	cfg.Attributes.Kubernetes.ServiceNameTemplate = "{{ .Meta.Name }}"
	cfg.Attributes.MetadataRetry = metadata.RetryConfig{
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

func TestV2ToRuntimeCloudEnricherRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.CloudMetadata.ClusterName = "cluster-a"
	cfg.CloudMetadata.Region = "us-gov-west-1"
	cfg.CloudMetadata.RefreshInterval = 45 * time.Second
	cfg.CloudMetadata.Route53.RefreshInterval = 7 * time.Minute
	cfg.CloudMetadata.Route53.HostedZoneIDs = []string{"Z123", "/hostedzone/Z456"}

	_, ext := RuntimeToV2(&cfg)
	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, cfg.CloudMetadata, got.CloudMetadata)
}

func TestDocumentToRuntimeCloudEnricher(t *testing.T) {
	t.Parallel()

	doc, _, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    enrich:
      enrichers:
        cloud:
          region: us-gov-west-1
          route53:
            refresh_interval: 2m
            hosted_zone_ids: [Z123, Z456]
      service_name:
        sources: [route53]
`))
	require.NoError(t, err)

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, transform.CloudMetadataConfig{
		Region:          "us-gov-west-1",
		RefreshInterval: obi.DefaultConfig.CloudMetadata.RefreshInterval,
		Route53:         transform.Route53MetadataConfig{RefreshInterval: 2 * time.Minute, HostedZoneIDs: []string{"Z123", "Z456"}},
	}, got.CloudMetadata)
	require.Equal(t, []transform.Source{transform.SourceRoute53}, got.NameResolver.Sources)
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
	require.Equal(t, obi.DefaultConfig.CloudMetadata, got.CloudMetadata)
	require.Equal(t, obi.DefaultConfig.Attributes.MetadataRetry, got.Attributes.MetadataRetry)
	require.Equal(t, obi.DefaultConfig.Attributes.Select, got.Attributes.Select)
	require.Equal(t, obi.DefaultConfig.Attributes.ExtraGroupAttributes, got.Attributes.ExtraGroupAttributes)
}

func TestV2ToRuntimeRejectsUnsupportedEnrichment(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		path   string
		mutate func(*schema.Enrich)
	}{
		{
			name: "enrich root",
			path: "enrich.custom",
			mutate: func(enrich *schema.Enrich) {
				enrich.AdditionalProperties = map[string]any{"custom": true}
			},
		},
		{
			name: "DNS enricher",
			path: "enrich.enrichers.dns",
			mutate: func(enrich *schema.Enrich) {
				enrich.Enrichers.AdditionalProperties = map[string]any{
					"dns": map[string]any{"enabled": true},
				}
			},
		},
		{
			name: "Kubernetes enricher",
			path: "enrich.enrichers.kubernetes.custom",
			mutate: func(enrich *schema.Enrich) {
				enrich.Enrichers.Kubernetes.AdditionalProperties = map[string]any{"custom": true}
			},
		},
		{
			name: "cloud enricher",
			path: "enrich.enrichers.cloud.custom",
			mutate: func(enrich *schema.Enrich) {
				enrich.Enrichers.Cloud.AdditionalProperties = map[string]any{"custom": true}
			},
		},
		{
			name: "Route53 enricher",
			path: "enrich.enrichers.cloud.route53.custom",
			mutate: func(enrich *schema.Enrich) {
				enrich.Enrichers.Cloud.Route53.AdditionalProperties = map[string]any{"custom": true}
			},
		},
		{
			name: "service name rules",
			path: "enrich.service_name.rules",
			mutate: func(enrich *schema.Enrich) {
				enrich.ServiceName.AdditionalProperties = map[string]any{"rules": []any{}}
			},
		},
		{
			name: "attribute rules",
			path: "enrich.attributes.rules",
			mutate: func(enrich *schema.Enrich) {
				enrich.Attributes.AdditionalProperties = map[string]any{"rules": []any{}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enrich := &schema.Enrich{}
			tc.mutate(enrich)
			_, err := V2ToRuntime(&schema.Extension{
				Version: schema.SupportedVersion,
				Enrich:  enrich,
			})
			require.ErrorContains(t, err, tc.path)
		})
	}
}
