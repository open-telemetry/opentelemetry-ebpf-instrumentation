// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/metadata/peer"
)

func TestConfigV1PeerMetadataDefaults(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	cfg, err := LoadConfig(strings.NewReader("peer_metadata:\n  enabled: true\n"))
	require.NoError(t, err)
	want := peer.DefaultConfig()
	want.Enabled = true
	require.Equal(t, want, cfg.PeerMetadata)
	require.NoError(t, cfg.ValidateStaticForReceiver())
}

func TestConfigV1PeerMetadataEnvironmentOverrides(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	settings := map[string]string{
		"ENABLED": "true", "LISTEN_ADDRESS": "127.0.0.1", "PORT": "9000",
		"PEER_CIDRS": "10.1.0.0/16,fd12::/64", "REFRESH_INTERVAL": "2s",
		"CALLER_TTL": "20s", "CACHE_TTL": "30s", "REQUEST_TIMEOUT": "500ms",
		"MAX_PEERS": "128", "MAX_CONCURRENT": "4", "MAX_CALLER_ENTRIES": "500",
		"MAX_RESPONSE_BYTES": "4096", "MAX_CACHE_BYTES": "8192", "TOKEN": "env-token",
		"TLS_ENABLED": "true", "TLS_CERT_FILE": "cert.pem", "TLS_KEY_FILE": "key.pem",
		"TLS_CA_FILE": "ca.pem", "TLS_SERVER_NAME": "agent.test",
	}
	for name, value := range settings {
		t.Setenv("OTEL_EBPF_PEER_METADATA_"+name, value)
	}
	cfg, err := LoadConfig(strings.NewReader(`peer_metadata:
  enabled: false
  port: 9001
  caller_ttl: 40s
  peer_cidrs: [192.168.0.0/16]
  token: yaml-token
  tls:
    cert_file: yaml-cert.pem
`))
	require.NoError(t, err)
	require.Equal(t, peer.Config{
		Enabled: true, ListenAddress: "127.0.0.1", Port: 9000,
		PeerCIDRs: []string{"10.1.0.0/16", "fd12::/64"}, RefreshInterval: 2 * time.Second,
		CallerTTL: 20 * time.Second, CacheTTL: 30 * time.Second, RequestTimeout: 500 * time.Millisecond,
		MaxPeers: 128, MaxConcurrent: 4, MaxCallerEntries: 500, MaxResponseBytes: 4096,
		MaxCacheBytes: 8192, Token: "env-token",
		TLS: peer.TLSConfig{Enabled: true, CertFile: "cert.pem", KeyFile: "key.pem", CAFile: "ca.pem", ServerName: "agent.test"},
	}, cfg.PeerMetadata)
	require.NoError(t, cfg.ValidateStaticForReceiver())
}

func TestConfigV1PeerMetadataYAML(t *testing.T) {
	cfg, err := LoadConfig(strings.NewReader(`peer_metadata:
  enabled: true
  port: 9000
  peer_cidrs: [10.1.0.0/16]
  caller_ttl: 20s
  token: yaml-token
  tls:
    enabled: true
    cert_file: cert.pem
    key_file: key.pem
`))
	require.NoError(t, err)
	require.Equal(t, 9000, cfg.PeerMetadata.Port)
	require.Equal(t, 20*time.Second, cfg.PeerMetadata.CallerTTL)
	require.Equal(t, []string{"10.1.0.0/16"}, cfg.PeerMetadata.PeerCIDRs)
	require.Equal(t, "yaml-token", cfg.PeerMetadata.Token)
	require.True(t, cfg.PeerMetadata.TLS.Enabled)
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	var decoded Config
	require.NoError(t, yaml.Unmarshal(data, &decoded))
	require.Equal(t, cfg.PeerMetadata, decoded.PeerMetadata)
}

func TestConfigV1PeerMetadataValidation(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	for _, field := range []string{"port: 0", "port: 65536", "caller_ttl: 0s", "max_peers: 0", "peer_cidrs: [invalid]", "tls: {enabled: true}"} {
		t.Run(field, func(t *testing.T) {
			cfg, err := LoadConfig(strings.NewReader("peer_metadata:\n  enabled: true\n  " + field + "\n"))
			require.NoError(t, err)
			require.ErrorContains(t, cfg.ValidateStaticForReceiver(), "peer metadata")
		})
	}
	t.Setenv("OTEL_EBPF_PEER_METADATA_CALLER_TTL", "not-a-duration")
	_, err := LoadConfig(nil)
	require.ErrorContains(t, err, "invalid duration")
}

func TestConfigPeerMetadataLogRedaction(t *testing.T) {
	cfg := DefaultConfig
	cfg.PeerMetadata.Token = "private-peer-token"
	data, err := yaml.Marshal(cfg.configForLogging())
	require.NoError(t, err)
	require.Contains(t, string(data), "peer_metadata:")
	require.Contains(t, string(data), "[REDACTED]")
	require.NotContains(t, string(data), "private-peer-token")
	require.Equal(t, "private-peer-token", cfg.PeerMetadata.Token)
}

func TestConfigPeerMetadataDelegatesValidation(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	cfg, err := LoadConfig(strings.NewReader("peer_metadata:\n  enabled: true\n  caller_ttl: 999us\n"))
	require.NoError(t, err)
	require.ErrorContains(t, cfg.ValidateStaticForReceiver(), "CallerTTL")
}

func TestConfigDisabledPeerMetadataSkipsValidation(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	cfg, err := LoadConfig(strings.NewReader("peer_metadata:\n  enabled: false\n  caller_ttl: 0s\n  max_peers: 0\n"))
	require.NoError(t, err)
	require.NoError(t, cfg.ValidateStaticForReceiver())
}
