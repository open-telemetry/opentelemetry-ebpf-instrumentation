// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

// DynamicSpan is a span declaration attached to a matching capture selector.
// Runtime-specific adapters interpret FunctionReference.
type DynamicSpan struct {
	Name              string
	FunctionReference string
}
