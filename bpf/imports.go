// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf

package bpf // import "go.opentelemetry.io/obi/bpf"

import (
	_ "go.opentelemetry.io/obi/bpf/bpfcore"
	_ "go.opentelemetry.io/obi/bpf/common"
	_ "go.opentelemetry.io/obi/bpf/generictracer"
	_ "go.opentelemetry.io/obi/bpf/gotracer"
	_ "go.opentelemetry.io/obi/bpf/gpuevent"
	_ "go.opentelemetry.io/obi/bpf/logger"
	_ "go.opentelemetry.io/obi/bpf/maps"
	_ "go.opentelemetry.io/obi/bpf/netolly"
	_ "go.opentelemetry.io/obi/bpf/pid"
	_ "go.opentelemetry.io/obi/bpf/rdns"
	_ "go.opentelemetry.io/obi/bpf/tctracer"
	_ "go.opentelemetry.io/obi/bpf/watcher"
)
