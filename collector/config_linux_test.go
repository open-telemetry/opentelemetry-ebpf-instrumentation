// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestReceiverConfigStructure(t *testing.T) {
	require.NoError(t, componenttest.CheckConfigStruct(defaultConfig()))
}

func TestReceiverConfigUnmarshalV2(t *testing.T) {
	cfg := newTestReceiverConfig(t)
	component := confmap.NewFromStringMap(map[string]any{
		"version": "2.0",
		"rules": []any{
			map[string]any{
				"action": "include",
				"match": map[string]any{
					"process": map[string]any{"open_ports": "8080"},
				},
			},
		},
		"channels": map[string]any{"buffer_len": 123},
	})

	require.NoError(t, component.Unmarshal(cfg))
	require.NoError(t, cfg.Validate())
	require.Equal(t, 123, cfg.runtime.ChannelBufferLen)
	require.Len(t, cfg.runtime.Discovery.Instrument, 2)

	var hasOpenPortSelector, hasDefaultSelector bool
	for _, selector := range cfg.runtime.Discovery.Instrument {
		if len(selector.OpenPorts.AllValues()) == 1 && selector.OpenPorts.AllValues()[0] == 8080 {
			hasOpenPortSelector = true
		}
		if selector.Path.IsSet() && selector.Path.MatchString("any-executable-path") && len(selector.OpenPorts.AllValues()) == 0 {
			hasDefaultSelector = true
		}
	}

	require.True(t, hasOpenPortSelector)
	require.True(t, hasDefaultSelector)
	require.NotNil(t, cfg.runtime.Traces.TracesConsumer)
	require.NotNil(t, cfg.runtime.OTELMetrics.MetricsConsumer)
}

func TestReceiverConfigUnmarshalLegacy(t *testing.T) {
	cfg := newTestReceiverConfig(t)
	component := confmap.NewFromStringMap(map[string]any{
		"open_port": "8080",
	})

	require.NoError(t, component.Unmarshal(cfg))
	require.NoError(t, cfg.Validate())
	require.Equal(t, []int{8080}, cfg.runtime.Port.AllValues())
}

func TestReceiverConfigRejectsStandaloneSections(t *testing.T) {
	layouts := []struct {
		name  string
		key   string
		value any
	}{
		{name: "v2", key: "version", value: "2.0"},
		{name: "legacy selector", key: "open_port", value: "8080"},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			for _, section := range []string{"enrich", "correlation", "daemon"} {
				t.Run(section, func(t *testing.T) {
					cfg := newTestReceiverConfig(t)
					component := confmap.NewFromStringMap(map[string]any{
						layout.key: layout.value,
						section:    map[string]any{},
					})

					err := component.Unmarshal(cfg)

					var notAllowed *schema.SectionNotAllowedError
					require.ErrorAs(t, err, &notAllowed)
					require.Equal(t, section, notAllowed.Section)
					require.Contains(t, err.Error(), "receiver config")
					require.Contains(t, err.Error(), "standalone mode")
				})
			}
		})
	}
}

func TestReceiverConfigDoesNotFallbackFromInvalidV2(t *testing.T) {
	tests := []struct {
		name      string
		component map[string]any
		check     func(*testing.T, error)
	}{
		{
			name: "unsupported version",
			component: map[string]any{
				"version":            "3.0",
				"channel_buffer_len": 123,
			},
			check: func(t *testing.T, err error) {
				var unsupported *schema.UnsupportedVersionError
				require.ErrorAs(t, err, &unsupported)
				require.Equal(t, "3.0", unsupported.Version)
			},
		},
		{
			name: "invalid capture value",
			component: map[string]any{
				"version": "2.0",
				"network": map[string]any{
					"capture": map[string]any{"source": "invalid"},
				},
				"channel_buffer_len": 123,
			},
			check: func(t *testing.T, err error) {
				require.Contains(t, err.Error(), "invalid source")
				var notV2 *schema.NotV2Error
				require.NotErrorAs(t, err, &notV2)
			},
		},
		{
			name: "standalone v2 layout with legacy selector",
			component: map[string]any{
				"file_format": "1.0",
				"extensions": map[string]any{
					"obi": map[string]any{
						"version": "2.0",
						"capture": map[string]any{},
					},
				},
				"open_port":          "8080",
				"channel_buffer_len": 123,
			},
			check: func(t *testing.T, err error) {
				var wrongLayout *schema.ReceiverLayoutError
				require.ErrorAs(t, err, &wrongLayout)
				var notV2 *schema.NotV2Error
				require.NotErrorAs(t, err, &notV2)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := newTestReceiverConfig(t)

			err := confmap.NewFromStringMap(test.component).Unmarshal(cfg)

			require.Error(t, err)
			test.check(t, err)
			require.Equal(t, obi.DefaultConfig.ChannelBufferLen, cfg.runtime.ChannelBufferLen)
		})
	}
}

func TestReceiverV2PipelineModes(t *testing.T) {
	tests := []struct {
		name    string
		traces  bool
		metrics bool
	}{
		{name: "traces", traces: true},
		{name: "metrics", metrics: true},
		{name: "traces and metrics", traces: true, metrics: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := newTestReceiverConfig(t)
			require.NoError(t, confmap.NewFromStringMap(map[string]any{
				"version": "2.0",
			}).Unmarshal(cfg))

			factory := NewFactory()
			settings := receivertest.NewNopSettings(typeStr)
			settings.ID = component.MustNewIDWithName("obi", test.name)

			if test.traces {
				consumer := consumertest.NewNop()
				receiver, err := factory.CreateTraces(t.Context(), settings, cfg, consumer)
				require.NoError(t, err)
				require.Same(t, consumer, cfg.runtime.Traces.TracesConsumer)
				t.Cleanup(func() {
					require.NoError(t, receiver.Shutdown(context.Background()))
				})
			}

			if test.metrics {
				consumer := consumertest.NewNop()
				receiver, err := factory.CreateMetrics(t.Context(), settings, cfg, consumer)
				require.NoError(t, err)
				require.Same(t, consumer, cfg.runtime.OTELMetrics.MetricsConsumer)
				t.Cleanup(func() {
					require.NoError(t, receiver.Shutdown(context.Background()))
				})
			}
		})
	}
}

func newTestReceiverConfig(t *testing.T) *receiverConfig {
	t.Helper()

	cfg, ok := NewFactory().CreateDefaultConfig().(*receiverConfig)
	require.True(t, ok)
	return cfg
}
