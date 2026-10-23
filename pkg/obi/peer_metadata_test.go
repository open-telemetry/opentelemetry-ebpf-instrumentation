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

func TestConfigV1PeerMetadataYAMLIgnored(t *testing.T) {
	cfg, err := LoadConfig(strings.NewReader(`peer_metadata:
  enabled: true
  port: 9000
  caller_ttl: not-a-duration
  peer_cidrs: [invalid]
  token: yaml-token
  tls:
    enabled: true
`))
	require.NoError(t, err)
	require.Equal(t, peer.DefaultConfig(), cfg.PeerMetadata)
}

func TestConfigV1PeerMetadataEnvironmentIgnored(t *testing.T) {
	settings := map[string]string{
		"ENABLED": "true", "LISTEN_ADDRESS": "127.0.0.1", "PORT": "9000",
		"PEER_CIDRS": "10.1.0.0/16,fd12::/64", "REFRESH_INTERVAL": "2s",
		"CALLER_TTL": "not-a-duration", "CACHE_TTL": "30s", "REQUEST_TIMEOUT": "500ms",
		"MAX_PEERS": "128", "MAX_CONCURRENT": "4", "MAX_CALLER_ENTRIES": "500",
		"MAX_RESPONSE_BYTES": "4096", "MAX_CACHE_BYTES": "8192", "TOKEN": "env-token",
		"TLS_ENABLED": "true", "TLS_CERT_FILE": "cert.pem", "TLS_KEY_FILE": "key.pem",
		"TLS_CA_FILE": "ca.pem", "TLS_SERVER_NAME": "agent.test",
	}
	for name, value := range settings {
		t.Setenv("OTEL_EBPF_PEER_METADATA_"+name, value)
	}
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	require.Equal(t, peer.DefaultConfig(), cfg.PeerMetadata)
}

func TestConfigV1PeerMetadataMapIgnored(t *testing.T) {
	cfg := DefaultConfig
	err := cfg.UnmarshalMap(map[string]any{
		"peer_metadata": map[string]any{"enabled": true, "port": 9000, "caller_ttl": "not-a-duration"},
	})
	require.NoError(t, err)
	require.Equal(t, peer.DefaultConfig(), cfg.PeerMetadata)
}

func TestConfigV1PeerMetadataNotMarshaled(t *testing.T) {
	cfg := DefaultConfig
	cfg.PeerMetadata.Enabled = true
	cfg.PeerMetadata.Token = "private-peer-token"
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NotContains(t, string(data), "peer_metadata:")
	require.NotContains(t, string(data), cfg.PeerMetadata.Token)
}

func TestConfigPeerMetadataRuntimeConfiguration(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	cfg.PeerMetadata.Enabled = true
	cfg.PeerMetadata.Port = 9000
	cfg.PeerMetadata.CallerTTL = 20 * time.Second
	cfg.PeerMetadata.PeerCIDRs = []string{"10.1.0.0/16"}
	require.NoError(t, cfg.ValidateStaticForReceiver())
	require.True(t, cfg.PeerMetadata.Enabled)
}

func TestConfigPeerMetadataRuntimeValidation(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	for _, test := range []struct {
		name string
		set  func(*peer.Config)
	}{
		{name: "port zero", set: func(c *peer.Config) { c.Port = 0 }},
		{name: "port too large", set: func(c *peer.Config) { c.Port = 65536 }},
		{name: "caller TTL", set: func(c *peer.Config) { c.CallerTTL = 0 }},
		{name: "max peers", set: func(c *peer.Config) { c.MaxPeers = 0 }},
		{name: "CIDR", set: func(c *peer.Config) { c.PeerCIDRs = []string{"invalid"} }},
		{name: "TLS", set: func(c *peer.Config) { c.TLS.Enabled = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := LoadConfig(nil)
			require.NoError(t, err)
			cfg.PeerMetadata.Enabled = true
			test.set(&cfg.PeerMetadata)
			require.ErrorContains(t, cfg.ValidateStaticForReceiver(), "peer metadata")
		})
	}
}

func TestConfigPeerMetadataDelegatesValidation(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	cfg.PeerMetadata.Enabled = true
	cfg.PeerMetadata.CallerTTL = 999 * time.Microsecond
	require.ErrorContains(t, cfg.ValidateStaticForReceiver(), "CallerTTL")
}

func TestConfigDisabledPeerMetadataSkipsValidation(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "python")
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	cfg.PeerMetadata = peer.Config{}
	require.NoError(t, cfg.ValidateStaticForReceiver())
}
