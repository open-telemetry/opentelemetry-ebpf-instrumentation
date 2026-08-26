// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package klogbridge routes k8s.io/klog output through OBI's default slog logger.
//
// It lives in a leaf package so both pkg/kube and pkg/kube/kubecache/meta can
// call it without creating an import cycle.
package klogbridge // import "go.opentelemetry.io/obi/pkg/kube/klogbridge"

import (
	"log/slog"
	"sync"

	"k8s.io/klog/v2"
)

var klogBridgeOnce sync.Once

// Install routes all k8s.io/klog output (client-go informers, reflectors, etc.)
// through the process-default slog logger, so it honors OBI's log level,
// format, and output stream instead of klog's default raw-stderr format.
//
// Safe to call multiple times; only the first call has an effect. Call after
// slog.SetDefault so the captured logger matches the embedding binary's config.
func Install() {
	klogBridgeOnce.Do(func() {
		klog.SetSlogLogger(slog.Default().With("component", "k8s.client-go"))
	})
}
