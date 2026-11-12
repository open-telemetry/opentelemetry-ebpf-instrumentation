// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// JobTracePIDs marks the processes whose services opted into job traces in eBPF.
type JobTracePIDs struct {
	pidEntries
}

func (j *JobTracePIDs) Write(m *ebpf.Map, pid app.PID, ns uint32, enabled bool) error {
	if !enabled {
		return j.remove(m, pid)
	}

	return j.put(m, pid, ns, uint8(1))
}

func (j *JobTracePIDs) Delete(m *ebpf.Map, pid app.PID) error {
	return j.remove(m, pid)
}
