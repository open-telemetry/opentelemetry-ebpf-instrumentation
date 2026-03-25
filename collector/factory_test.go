// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	require.NotNil(t, f)
}

// TestNewFactoryUnsupportedPlatform verifies that on platforms where OBI is not
// supported (non-Linux or non-amd64/arm64), the factory is present but returns
// a clear error when a receiver is created — consistent with the journaldreceiver
// pattern used in opentelemetry-collector-contrib.
func TestNewFactoryUnsupportedPlatform(t *testing.T) {
	supported := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	if supported {
		t.Skip("skipping unsupported-platform test on a supported platform")
	}

	typ, err := component.NewType("obi")
	require.NoError(t, err)
	settings := receivertest.NewNopSettings(typ)

	_, err = BuildTracesReceiver()(t.Context(), settings, defaultConfig(), consumertest.NewNop())
	require.ErrorIs(t, err, errUnsupportedPlatform)

	_, err = BuildMetricsReceiver()(t.Context(), settings, defaultConfig(), consumertest.NewNop())
	require.ErrorIs(t, err, errUnsupportedPlatform)
}

func TestCreateProfilesReceiver(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping test on non-linux platform")
	}
	for _, tt := range []struct {
		name   string
		config component.Config

		wantError error
	}{
		{
			name:   "Default config",
			config: defaultConfig(),
		},
		{
			name:      "Nil config",
			wantError: errInvalidConfig,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			typ, err := component.NewType("TracesReceiver")
			require.NoError(t, err)
			_, err = BuildTracesReceiver()(
				t.Context(),
				receivertest.NewNopSettings(typ),
				tt.config,
				consumertest.NewNop(),
			)
			require.ErrorIs(t, err, tt.wantError)
		})
	}
}
