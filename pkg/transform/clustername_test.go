// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube"
)

func newTestKubeConfig(t *testing.T, serverURL string) string {
	t.Helper()
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ` + serverURL + `
    insecure-skip-tls-verify: true
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user: {}
`
	p := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(p, []byte(kubeconfig), 0o600))
	return p
}

func TestOpenshiftClusterNameFetcher(t *testing.T) {
	t.Run("returns infrastructureName on success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, openshiftInfraPath, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":{"infrastructureName":"my-cluster"}}`))
		}))
		defer srv.Close()

		mp := kube.NewMetadataProvider(kube.MetadataConfig{
			KubeConfigPath: newTestKubeConfig(t, srv.URL),
		}, imetrics.NoopReporter{})

		fetcher := openshiftClusterNameFetcher(mp)
		name, err := fetcher(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "my-cluster", name)
	})

	t.Run("returns error on non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		mp := kube.NewMetadataProvider(kube.MetadataConfig{
			KubeConfigPath: newTestKubeConfig(t, srv.URL),
		}, imetrics.NoopReporter{})

		fetcher := openshiftClusterNameFetcher(mp)
		_, err := fetcher(t.Context())
		assert.ErrorContains(t, err, "OpenShift API returned 404")
	})

	t.Run("returns error on empty infrastructureName", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":{"infrastructureName":""}}`))
		}))
		defer srv.Close()

		mp := kube.NewMetadataProvider(kube.MetadataConfig{
			KubeConfigPath: newTestKubeConfig(t, srv.URL),
		}, imetrics.NoopReporter{})

		fetcher := openshiftClusterNameFetcher(mp)
		_, err := fetcher(t.Context())
		assert.ErrorContains(t, err, "empty infrastructureName")
	})
}

func TestFetchClusterNameOpenShiftWithCloudDetectionDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != openshiftInfraPath {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":{"infrastructureName":"my-cluster"}}`))
	}))
	defer server.Close()

	mp := kube.NewMetadataProvider(kube.MetadataConfig{
		KubeConfigPath: newTestKubeConfig(t, server.URL),
	}, imetrics.NoopReporter{})

	name := fetchClusterName(t.Context(), mp, false)

	assert.Equal(t, "my-cluster", name)
}

func TestFetchClusterNameCloudDetection(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	kubeServer := httptest.NewServer(http.NotFoundHandler())
	defer kubeServer.Close()

	var cloudRequests atomic.Int32

	cloudServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloudRequests.Add(1)
		http.NotFound(w, r)
	}))
	defer cloudServer.Close()

	proxyURL, err := url.Parse(cloudServer.URL)
	require.NoError(t, err)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	originalTransport := metadataClient.Transport
	metadataClient.Transport = transport
	t.Cleanup(func() {
		metadataClient.Transport = originalTransport
		transport.CloseIdleConnections()
	})

	tests := []struct {
		name             string
		enabled          bool
		expectedRequests int32
	}{
		{
			name:             "disabled",
			enabled:          false,
			expectedRequests: 0,
		},
		{
			name:             "enabled",
			enabled:          true,
			expectedRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cloudRequests.Store(0)

			mp := kube.NewMetadataProvider(kube.MetadataConfig{
				KubeConfigPath: newTestKubeConfig(t, kubeServer.URL),
			}, imetrics.NoopReporter{})

			name := fetchClusterName(t.Context(), mp, tt.enabled)

			assert.Empty(t, name)
			assert.Equal(t, tt.expectedRequests, cloudRequests.Load())
		})
	}
}

func TestKubeClusterNameConfiguredWithCloudDetectionDisabled(t *testing.T) {
	cfg := &KubernetesDecorator{
		ClusterName: "configured-cluster",
	}

	name := KubeClusterName(t.Context(), cfg, false, nil)

	assert.Equal(t, "configured-cluster", name)
}
