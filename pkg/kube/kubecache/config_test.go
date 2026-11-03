// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubecache

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigTLS(t *testing.T) {
	cfg, err := LoadConfig(strings.NewReader(`
tls:
  enabled: true
  cert_file: /certs/tls.crt
  key_file: /certs/tls.key
`))
	require.NoError(t, err)
	require.Equal(t, TLSConfig{Enabled: true, CertFile: "/certs/tls.crt", KeyFile: "/certs/tls.key"}, cfg.TLS)

	t.Setenv("OTEL_EBPF_K8S_CACHE_TLS_CLIENT_CA_FILE", "/certs/ca.crt")
	cfg, err = LoadConfig(strings.NewReader("tls:\n  enabled: true\n  cert_file: a\n  key_file: b\n"))
	require.NoError(t, err)
	require.Equal(t, "/certs/ca.crt", cfg.TLS.ClientCAFile)
}

func TestLoadConfigRejectsIncompleteTLS(t *testing.T) {
	t.Setenv("OTEL_EBPF_K8S_CACHE_TLS_ENABLED", "true")
	_, err := LoadConfig(nil)
	require.ErrorContains(t, err, "tls.cert_file and tls.key_file are required")
}
