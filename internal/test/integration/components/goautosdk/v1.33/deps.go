// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goautosdkdeps // import "go.opentelemetry.io/obi/internal/test/integration/components/goautosdk"

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var (
	_ = otel.Tracer
	_ = attribute.String
	_ = codes.Error
	_ trace.Span
)
