// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestLogsConfig_Enabled(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg := LogsConfig{}
		assert.False(t, cfg.Enabled())
	})

	t.Run("enabled with an endpoint", func(t *testing.T) {
		cfg := LogsConfig{LogsEndpoint: "http://localhost:4318"}
		assert.True(t, cfg.Enabled())
	})

	t.Run("enabled via debug protocol", func(t *testing.T) {
		cfg := LogsConfig{LogsProtocol: ProtocolDebug}
		assert.True(t, cfg.Enabled())
	})

	t.Run("enabled via injected consumer", func(t *testing.T) {
		cfg := LogsConfig{LogsConsumer: fakeLogsConsumer{}}
		assert.True(t, cfg.Enabled())
	})
}

func TestHTTPLogsEndpoint(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	cfg := LogsConfig{
		CommonEndpoint: "https://localhost:3131",
		LogsEndpoint:   "https://localhost:3232/v1/logs",
	}
	opts, err := HTTPLogsEndpointOptions(&cfg)
	require.NoError(t, err)
	assert.Equal(t, "https", opts.Scheme)
	assert.Equal(t, "localhost:3232", opts.Endpoint)
	assert.Equal(t, "/v1/logs", opts.URLPath)
}

func TestHTTPLogsEndpoint_CommonOnly(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	cfg := LogsConfig{
		CommonEndpoint: "https://localhost:3131/otlp",
	}
	opts, err := HTTPLogsEndpointOptions(&cfg)
	require.NoError(t, err)
	assert.Equal(t, "https", opts.Scheme)
	assert.Equal(t, "localhost:3131", opts.Endpoint)
	assert.Equal(t, "/otlp", opts.BaseURLPath)
	assert.Equal(t, "/otlp/v1/logs", opts.URLPath)
}

func TestLogsConfig_NormalizeQueueConfig(t *testing.T) {
	t.Run("defaults queue size to 4x batch size", func(t *testing.T) {
		cfg := LogsConfig{BatchMaxSize: 100}
		require.NoError(t, cfg.NormalizeQueueConfig())
		assert.Equal(t, 400, cfg.QueueSize)
	})

	t.Run("rejects queue size smaller than 2x batch size", func(t *testing.T) {
		cfg := LogsConfig{BatchMaxSize: 100, QueueSize: 50}
		require.Error(t, cfg.NormalizeQueueConfig())
	})
}

type fakeLogsConsumer struct{}

func (fakeLogsConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (fakeLogsConsumer) ConsumeLogs(_ context.Context, _ plog.Logs) error { return nil }
