// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import "github.com/cilium/ebpf"

// ShrinkActiveRequestsMap avoids allocating the full shared map when collection is disabled.
func ShrinkActiveRequestsMap(spec *ebpf.CollectionSpec) {
	for _, name := range []string{"active_requests"} {
		if m := spec.Maps[name]; m != nil {
			m.MaxEntries = 1
		}
	}
}
