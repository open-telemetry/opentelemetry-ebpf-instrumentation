// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
	"go.opentelemetry.io/obi/pkg/obi"
)

func peerMetadataYAML(body string) string {
	return "file_format: \"1.0\"\nextensions:\n  obi:\n    version: \"2.0\"\n    enrich:\n      enrichers:\n        peer_metadata:\n" + body
}

func TestPeerMetadataV2DefaultsAndRoundTrip(t *testing.T) {
	_, ext, err := schema.ParseStandaloneYAML([]byte(peerMetadataYAML("          enabled: true\n")))
	require.NoError(t, err)
	cfg, err := V2ToRuntime(ext)
	require.NoError(t, err)
	want := peer.DefaultConfig()
	want.Enabled = true
	require.Equal(t, want, cfg.PeerMetadata)
	cfg.PeerMetadata.CallerTTL = 20 * time.Second
	cfg.PeerMetadata.PeerCIDRs = []string{"10.1.0.0/16"}
	cfg.PeerMetadata.Token = "secret"
	cfg.PeerMetadata.TLS = peer.TLSConfig{Enabled: true, CertFile: "cert", KeyFile: "key", CAFile: "ca", ServerName: "agent"}
	_, exported := RuntimeToV2(cfg)
	roundTrip, err := V2ToRuntime(exported)
	require.NoError(t, err)
	require.Equal(t, cfg.PeerMetadata, roundTrip.PeerMetadata)
}

func TestPeerMetadataV2Validation(t *testing.T) {
	for _, field := range []string{
		"port: 65536", "port: 0", "caller_ttl: 0s", "cache_ttl: -1s", "refresh_interval: 0s",
		"peer_cidrs: [invalid]", "max_peers: 0", "max_concurrent: -1", "max_cache_bytes: 1",
		"request_timeout: 0s", "max_caller_entries: 0", "max_response_bytes: 0", "max_cache_bytes: 0",
		"tls: {enabled: true}", "unsupported: true", "tls: {unsupported: true}",
	} {
		t.Run(field, func(t *testing.T) {
			body := "          enabled: true\n          " + field + "\n"
			_, ext, err := schema.ParseStandaloneYAML([]byte(peerMetadataYAML(body)))
			require.NoError(t, err)
			_, err = V2ToRuntime(ext)
			require.Error(t, err)
			require.Contains(t, err.Error(), "peer_metadata")
		})
	}
}

func TestPeerMetadataV1ToV2RoundTrip(t *testing.T) {
	cfg, err := obi.LoadConfig(strings.NewReader(`peer_metadata:
  enabled: true
  listen_address: 127.0.0.1
  port: 9000
  peer_cidrs: [10.1.0.0/16]
  caller_ttl: 20s
  token: shared-token
  tls:
    enabled: true
    cert_file: cert.pem
    key_file: key.pem
    ca_file: ca.pem
    server_name: agent.test
`))
	require.NoError(t, err)
	_, extension := RuntimeToV2(cfg)
	restored, err := V2ToRuntime(extension)
	require.NoError(t, err)
	require.Equal(t, cfg.PeerMetadata, restored.PeerMetadata)
}

func TestPeerMetadataV2UsesValidationTags(t *testing.T) {
	_, ext, err := schema.ParseStandaloneYAML([]byte(peerMetadataYAML("          enabled: true\n          caller_ttl: 999us\n")))
	require.NoError(t, err)
	_, err = V2ToRuntime(ext)
	var validationErrors validator.ValidationErrors
	require.ErrorAs(t, err, &validationErrors)
	require.Len(t, validationErrors, 1)
	require.Equal(t, "CallerTTL", validationErrors[0].Field())
}

func TestDisabledPeerMetadataV2SkipsValidation(t *testing.T) {
	_, ext, err := schema.ParseStandaloneYAML([]byte(peerMetadataYAML("          enabled: false\n          caller_ttl: 0s\n          max_peers: 0\n")))
	require.NoError(t, err)
	cfg, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.False(t, cfg.PeerMetadata.Enabled)
}
