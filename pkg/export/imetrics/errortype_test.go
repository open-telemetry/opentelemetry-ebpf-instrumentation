// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/internal/errtype"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

// The OTLP exporters wrap every send error, so the shapes below are the ones that actually
// reach the reporter. A classifier that reads only the outermost error reports the wrapper
// type for all of them.
func TestExportErrorType(t *testing.T) {
	refused := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: syscall.ECONNREFUSED,
	}

	for _, tc := range []struct {
		name     string
		err      error
		expected string
	}{
		{"nil", nil, errtype.Other},
		{
			"grpc status wrapped by the exporter",
			fmt.Errorf("failed to upload metrics: %w", status.Error(codes.Unavailable, "10.1.2.3:4317")),
			"UNAVAILABLE",
		},
		{
			"grpc status joined and wrapped",
			fmt.Errorf("failed to upload metrics: %w",
				errors.Join(nil, status.Error(codes.ResourceExhausted, "quota"))),
			"RESOURCE_EXHAUSTED",
		},
		{
			"network error joined and wrapped",
			fmt.Errorf("failed to upload metrics: %w", errors.Join(nil, refused)),
			"*net.OpError",
		},
		{
			"context deadline wrapped",
			fmt.Errorf("failed to upload metrics: %w", context.DeadlineExceeded),
			"DEADLINE_EXCEEDED",
		},
		{
			"context cancellation wrapped",
			fmt.Errorf("failed to upload metrics: %w", context.Canceled),
			"CANCELLED",
		},
		{"plain error", errors.New("plain failure"), "*errors.errorString"},
		{
			"status outside the grpc enum is never reported as a made-up value",
			status.New(codes.Code(42), "bogus").Err(),
			"*status.Error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ExportErrorType(tc.err))
		})
	}
}

// Drives a real OTLP/HTTP exporter, the default metrics protocol, against a port nothing
// listens on. Guards against the classifier degrading to a single wrapper type for every
// transport failure.
func TestExportErrorTypeFromRealOTLPExporter(t *testing.T) {
	port := testutil.FreeTCPPort(t)

	exporter, err := otlpmetrichttp.New(t.Context(),
		otlpmetrichttp.WithEndpoint(fmt.Sprintf("127.0.0.1:%d", port)),
		otlpmetrichttp.WithInsecure(),
		otlpmetrichttp.WithTimeout(2*time.Second),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
	)
	require.NoError(t, err)

	exportErr := exporter.Export(t.Context(), &metricdata.ResourceMetrics{})
	require.Error(t, exportErr)

	errorType := ExportErrorType(exportErr)
	assert.NotEqual(t, "*fmt.wrapError", errorType)
	assert.NotEqual(t, "*errors.joinError", errorType)
}
