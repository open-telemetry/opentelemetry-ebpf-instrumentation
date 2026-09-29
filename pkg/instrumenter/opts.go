// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter // import "go.opentelemetry.io/obi/pkg/instrumenter"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// Option that override the instantiation of the instrumenter
type Option func(info *global.ContextInfo)

// WithDynamicSelector passes the given dynamic selector into OBI. The caller creates it with
// discover.NewDynamicSelector(), passes it here, and then calls AddPIDs, AddPID, AddK8sWorkload,
// GetPID, SetPID, RemovePIDs, or GetPIDs on it directly, or targets specific signals via subviews
// such as Traces(), AppMetrics(), NetworkMetrics(), and StatsMetrics().
//
// Root AddPIDs/RemovePIDs/AddK8sWorkload preserve the legacy behavior and apply to all supported
// signals. Service name and resource attributes set via AddPID, AddK8sWorkload, or SetPID are
// shared across all signals. SetPID updates live FileInfo for instrumented PIDs; traces and app
// metrics read it at export time. Network and stats metrics decorate flow records with service
// name/namespace by pod IP.
func WithDynamicSelector(sel *discover.DynamicSelector) Option {
	return func(info *global.ContextInfo) {
		info.DynamicSelector = sel
	}
}

// OverrideAppExportQueue allows to override the queue used to export the spans.
// This is useful to run the instrumenter in vendored mode, and you want to provide your
// own spans exporter.
// This queue will be used also by other bundled exported (OTEL, Prometheus...) if
// they are configured to run.
// See examples/vendoring/vendoring.go for an example of invocation.
func OverrideAppExportQueue(q *msg.Queue[[]request.Span]) Option {
	return func(info *global.ContextInfo) {
		info.OverrideAppExportQueue = q
	}
}
