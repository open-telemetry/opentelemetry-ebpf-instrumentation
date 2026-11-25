// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import "github.com/cilium/ebpf"

// ShrinkRustMaps avoids allocating Rust instrumentation state when it is off.
// The generic and Go tracers and the tpinjector share these internal maps, so
// all of them must call it.
func ShrinkRustMaps(spec *ebpf.CollectionSpec) {
	for _, name := range []string{"rust_capabilities", "rust_threads", "rust_task_context"} {
		if m := spec.Maps[name]; m != nil {
			m.MaxEntries = 1
		}
	}
}
