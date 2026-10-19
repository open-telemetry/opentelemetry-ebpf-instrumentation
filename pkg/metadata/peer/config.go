// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package peer defines peer metadata configuration and its wire protocol.
package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
)

const DefaultPort = 8998

var configValidator = validator.New(validator.WithRequiredStructEnabled())

// PeerMetadataConfig configures peer metadata exchange.
type PeerMetadataConfig struct {
	Enabled          bool                  `yaml:"enabled" env:"OTEL_EBPF_PEER_METADATA_ENABLED"`
	ListenAddress    string                `yaml:"listen_address" env:"OTEL_EBPF_PEER_METADATA_LISTEN_ADDRESS"`
	Port             int                   `yaml:"port" env:"OTEL_EBPF_PEER_METADATA_PORT"`
	PeerCIDRs        []string              `yaml:"peer_cidrs" env:"OTEL_EBPF_PEER_METADATA_PEER_CIDRS" envSeparator:","`
	RefreshInterval  time.Duration         `yaml:"refresh_interval" env:"OTEL_EBPF_PEER_METADATA_REFRESH_INTERVAL" validate:"gte=1ms"`
	CallerTTL        time.Duration         `yaml:"caller_ttl" env:"OTEL_EBPF_PEER_METADATA_CALLER_TTL" validate:"gte=1ms"`
	CacheTTL         time.Duration         `yaml:"cache_ttl" env:"OTEL_EBPF_PEER_METADATA_CACHE_TTL" validate:"gte=1ms"`
	RequestTimeout   time.Duration         `yaml:"request_timeout" env:"OTEL_EBPF_PEER_METADATA_REQUEST_TIMEOUT" validate:"gte=1ms"`
	MaxPeers         int                   `yaml:"max_peers" env:"OTEL_EBPF_PEER_METADATA_MAX_PEERS" validate:"gt=0"`
	MaxConcurrent    int                   `yaml:"max_concurrent" env:"OTEL_EBPF_PEER_METADATA_MAX_CONCURRENT" validate:"gt=0"`
	MaxCallerEntries int                   `yaml:"max_caller_entries" env:"OTEL_EBPF_PEER_METADATA_MAX_CALLER_ENTRIES" validate:"gt=0"`
	MaxResponseBytes int                   `yaml:"max_response_bytes" env:"OTEL_EBPF_PEER_METADATA_MAX_RESPONSE_BYTES" validate:"gt=0"`
	MaxCacheBytes    int                   `yaml:"max_cache_bytes" env:"OTEL_EBPF_PEER_METADATA_MAX_CACHE_BYTES" validate:"gt=0"`
	Token            string                `yaml:"token" env:"OTEL_EBPF_PEER_METADATA_TOKEN"`
	TLS              PeerMetadataTLSConfig `yaml:"tls"`
}

// Config retains the public runtime configuration name.
type Config = PeerMetadataConfig

type PeerMetadataTLSConfig struct {
	Enabled    bool   `yaml:"enabled" env:"OTEL_EBPF_PEER_METADATA_TLS_ENABLED"`
	CertFile   string `yaml:"cert_file" env:"OTEL_EBPF_PEER_METADATA_TLS_CERT_FILE"`
	KeyFile    string `yaml:"key_file" env:"OTEL_EBPF_PEER_METADATA_TLS_KEY_FILE"`
	CAFile     string `yaml:"ca_file" env:"OTEL_EBPF_PEER_METADATA_TLS_CA_FILE"`
	ServerName string `yaml:"server_name" env:"OTEL_EBPF_PEER_METADATA_TLS_SERVER_NAME"`
}

type TLSConfig = PeerMetadataTLSConfig

func DefaultConfig() Config {
	return Config{
		Port:             DefaultPort,
		RefreshInterval:  10 * time.Second,
		CallerTTL:        time.Minute,
		CacheTTL:         time.Minute,
		RequestTimeout:   2 * time.Second,
		MaxPeers:         1024,
		MaxConcurrent:    8,
		MaxCallerEntries: 16384,
		MaxResponseBytes: 1 << 20,
		MaxCacheBytes:    64 << 20,
	}
}

// WithDefaults returns a copy with defaults for unspecified runtime settings.
func (c Config) WithDefaults() Config {
	d := DefaultConfig()
	setIntDefault(&c.Port, d.Port)
	setIntDefault(&c.MaxPeers, d.MaxPeers)
	setIntDefault(&c.MaxConcurrent, d.MaxConcurrent)
	setIntDefault(&c.MaxCallerEntries, d.MaxCallerEntries)
	setIntDefault(&c.MaxResponseBytes, d.MaxResponseBytes)
	setIntDefault(&c.MaxCacheBytes, d.MaxCacheBytes)
	setDurationDefault(&c.RefreshInterval, d.RefreshInterval)
	setDurationDefault(&c.CallerTTL, d.CallerTTL)
	setDurationDefault(&c.CacheTTL, d.CacheTTL)
	setDurationDefault(&c.RequestTimeout, d.RequestTimeout)
	c.PeerCIDRs = append([]string(nil), c.PeerCIDRs...)
	return c
}

func setIntDefault(value *int, fallback int) {
	if *value == 0 {
		*value = fallback
	}
}

func setDurationDefault(value *time.Duration, fallback time.Duration) {
	if *value == 0 {
		*value = fallback
	}
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Port < 1 || c.Port > 65535 {
		return errors.New("peer metadata port must be between 1 and 65535")
	}

	if c.ListenAddress != "" {
		if _, err := netip.ParseAddr(c.ListenAddress); err != nil {
			return fmt.Errorf("peer metadata listen_address: %w", err)
		}
	}

	for _, cidr := range c.PeerCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("peer metadata peer_cidrs: %w", err)
		}
	}

	if err := configValidator.Struct(c); err != nil {
		return fmt.Errorf("peer metadata: %w", err)
	}

	if strings.ContainsAny(c.Token, "\r\n") {
		return errors.New("peer metadata token must not contain newlines")
	}

	if c.TLS.Enabled && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return errors.New("peer metadata TLS requires cert_file and key_file")
	}

	if c.MaxCacheBytes < c.MaxResponseBytes {
		return errors.New("peer metadata max_cache_bytes must be at least max_response_bytes")
	}

	return nil
}
