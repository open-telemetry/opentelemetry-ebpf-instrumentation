// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLogsHeaders(t *testing.T) {
	c := LogsConfig{InjectHeaders: func(h map[string]string) { h["config"] = "yes"; h["override"] = "config" }}
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "shared=one,override=common")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "override=logs")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "override=traces")
	require.Equal(t, map[string]string{"config": "yes", "shared": "one", "override": "logs"}, c.Headers())
}

func TestLogsValidate(t *testing.T) {
	c := LogsConfig{Protocol: ProtocolDebug, BatchMaxSize: 2, QueueSize: 8, BatchTimeout: time.Second}
	require.True(t, c.Enabled())
	require.NoError(t, c.Validate())

	c.Protocol = ProtocolGRPC
	require.False(t, c.Enabled())

	c.Endpoint = "localhost:4317"
	require.ErrorContains(t, c.Validate(), "endpoint must be")
	c.Endpoint = "http://localhost:4317"
	require.NoError(t, c.Validate())
	c.Endpoint = "unix:///tmp/otlp.sock"
	require.NoError(t, c.Validate())

	c.QueueSize = 3
	require.ErrorContains(t, c.Validate(), "max_queue_size")
}
