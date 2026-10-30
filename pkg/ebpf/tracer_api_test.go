// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf_test

import (
	"os"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/ebpf"
)

// Compile on Linux and Darwin to guard the exported attachment signatures.
var (
	_ func(*ebpf.ProcessTracer, *link.Executable, *ebpf.Instrumentable) error = (*ebpf.ProcessTracer).NewExecutable
	_ func(*ebpf.ProcessTracer, *os.File, *ebpf.Instrumentable) error         = (*ebpf.ProcessTracer).NewExecutableFile
)
