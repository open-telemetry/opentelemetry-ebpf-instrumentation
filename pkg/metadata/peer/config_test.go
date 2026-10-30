// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestRuntimeDefaultsAndValidation(t *testing.T) {
	cfg := (Config{Enabled: true, PeerCIDRs: []string{"10.1.0.0/16"}}).WithDefaults()
	require.NoError(t, cfg.Validate())
	require.Equal(t, time.Minute, cfg.CallerTTL)
	require.Equal(t, 1024, cfg.MaxPeers)
	cfg.Port = -1
	require.Error(t, cfg.Validate())
	cfg.Enabled = false
	require.NoError(t, cfg.Validate())
}

func TestConfigLimitValidationTags(t *testing.T) {
	for _, test := range []struct {
		field   string
		invalid string
		valid   string
	}{
		{field: "refresh_interval", invalid: "999us", valid: "1ms"},
		{field: "caller_ttl", invalid: "999us", valid: "1ms"},
		{field: "cache_ttl", invalid: "999us", valid: "1ms"},
		{field: "request_timeout", invalid: "999us", valid: "1ms"},
		{field: "max_peers", invalid: "0", valid: "1"},
		{field: "max_concurrent", invalid: "0", valid: "1"},
		{field: "max_caller_entries", invalid: "0", valid: "1"},
		{field: "max_response_bytes", invalid: "0", valid: "1"},
		{field: "max_cache_bytes", invalid: "0", valid: "1"},
		{field: "mode", invalid: "unknown", valid: "central"},
	} {
		t.Run(test.field, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			cfg.MaxResponseBytes = 1
			require.NoError(t, yaml.Unmarshal([]byte(test.field+": "+test.invalid), &cfg))
			var validationErrors validator.ValidationErrors
			require.ErrorAs(t, cfg.Validate(), &validationErrors)
			require.Len(t, validationErrors, 1)
			cfg.Enabled = false
			require.NoError(t, cfg.Validate())
			cfg.Enabled = true
			require.NoError(t, yaml.Unmarshal([]byte(test.field+": "+test.valid), &cfg))
			require.NoError(t, cfg.Validate())
		})
	}
}

func TestBearerTokenRequiresTLS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Token = "shared-secret"
	err := cfg.Validate()
	require.ErrorContains(t, err, "token requires TLS")
	require.NotContains(t, err.Error(), cfg.Token)

	cfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: "cert.pem", KeyFile: "key.pem"}
	require.NoError(t, cfg.Validate())
	cfg.TLS.Enabled = false
	cfg.Token = ""
	require.NoError(t, cfg.Validate())
	cfg.Enabled = false
	cfg.Token = "shared-secret"
	require.NoError(t, cfg.Validate())
}
