// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flow // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow"

import "github.com/cilium/ebpf"

type InternalMetrics struct {
	droppedFlowBytes *ebpf.Map
}

func StartInternalMetrics(droppedFlowBytes *ebpf.Map) (InternalMetrics, error) {
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		_ = droppedFlowBytes.Close()
		return InternalMetrics{}, err
	}
	// initialize all the counters to 0
	if err := droppedFlowBytes.Put(uint32(0), make([]uint64, possibleCPUs)); err != nil {
		_ = droppedFlowBytes.Close()
		return InternalMetrics{}, err
	}

	return InternalMetrics{
		droppedFlowBytes: droppedFlowBytes,
	}, nil
}

func (fm *InternalMetrics) Close() error {
	return fm.droppedFlowBytes.Close()
}

func (fm *InternalMetrics) Count() (uint64, error) {
	if fm.droppedFlowBytes == nil {
		return 0, nil
	}

	var perCPUCounts []uint64
	if err := fm.droppedFlowBytes.Lookup(uint32(0), &perCPUCounts); err != nil {
		return 0, err
	}

	var total uint64
	for _, count := range perCPUCounts {
		total += count
	}

	return total, nil
}
