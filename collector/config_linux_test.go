// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/confmap"

	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

func TestReceiverConfigUnmarshalV2(t *testing.T) {
	cfg := newReceiverConfig()
	component := confmap.NewFromStringMap(map[string]any{
		"version": "2.0",
		"policy": map[string]any{
			"default_action": "include",
		},
		"channels": map[string]any{
			"buffer_len": 123,
		},
	})

	require.NoError(t, cfg.Unmarshal(component))
	require.Equal(t, 123, cfg.runtime.ChannelBufferLen)
}

func TestReceiverConfigValidateV2(t *testing.T) {
	cfg := newReceiverConfig()
	component := confmap.NewFromStringMap(map[string]any{
		"version": "2.0",
		"policy": map[string]any{
			"default_action": "include",
		},
	})

	require.NoError(t, cfg.Unmarshal(component))
	require.NoError(t, cfg.Validate())
}

func TestReceiverConfigUnmarshalLegacy(t *testing.T) {
	cfg := newReceiverConfig()
	component := confmap.NewFromStringMap(map[string]any{})

	require.NoError(t, cfg.Unmarshal(component))
	require.NotNil(t, cfg.runtime)
}

func TestReceiverConfigRejectsStandaloneSections(t *testing.T) {
	cfg := newReceiverConfig()
	component := confmap.NewFromStringMap(map[string]any{
		"version": "2.0",
		"policy": map[string]any{
			"default_action": "include",
		},
		"daemon": map[string]any{
			"logging": map[string]any{
				"level": "INFO",
			},
		},
	})

	err := cfg.Unmarshal(component)
	require.Error(t, err)

	var notAllowed *obiv2.SectionNotAllowedError
	require.True(t, errors.As(err, &notAllowed))
	require.Equal(t, "daemon", notAllowed.Section)
}
