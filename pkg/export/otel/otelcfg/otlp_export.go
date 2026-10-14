// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import "context"

// OTLPExportFunc sends a protobuf-encoded OTLP export request. The request's
// signal is determined by the configuration field using this function.
type OTLPExportFunc func(context.Context, []byte) error
