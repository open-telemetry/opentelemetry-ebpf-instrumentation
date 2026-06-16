// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
