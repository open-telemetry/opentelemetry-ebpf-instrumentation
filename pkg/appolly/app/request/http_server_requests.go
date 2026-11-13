// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

// HTTPServerRequestDelta carries request attributes and a change in active requests.
type HTTPServerRequestDelta struct {
	// Span carries attributes only; it is not a completed trace span.
	Span  Span
	Delta int64
}
