// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccumulate(t *testing.T) {
	type testCase struct {
		input    []NetFlowMetrics
		expected NetFlowMetrics
	}
	tcs := []testCase{{
		input: []NetFlowMetrics{
			{Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b, Flags: 1, IfaceDirection: 1},
		},
		expected: NetFlowMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b, Flags: 1, IfaceDirection: 1,
		},
	}, {
		input: []NetFlowMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e, Flags: 1, IfaceDirection: 0},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeNs: 0x17f3e9633a7f, EndMonoTimeNs: 0x17f3e96f164e, Flags: 1, IfaceDirection: 1},
		},
		expected: NetFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e, Flags: 1, IfaceDirection: 0,
		},
	}, {
		// the slot of a CPU that added packets to an entry another CPU created has no start time,
		// direction or initiator, whatever the order the slots are read in
		input: []NetFlowMetrics{
			{Packets: 0x4, Bytes: 0x100, StartMonoTimeNs: 0, EndMonoTimeNs: 0x17f3e979816e, Flags: 2},
			{Packets: 0x1, Bytes: 0x40, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e9613a7f, Flags: 1, IfaceDirection: 1, Initiator: 2},
			{Packets: 0x2, Bytes: 0x80, StartMonoTimeNs: 0, EndMonoTimeNs: 0x17f3e96f164e, Flags: 1},
		},
		expected: NetFlowMetrics{
			Packets: 0x7, Bytes: 0x1c0, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e, Flags: 3, IfaceDirection: 1, Initiator: 2,
		},
	}}
	for i, tc := range tcs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			agg := NetFlowMetrics{}
			for _, mt := range tc.input {
				agg.Accumulate(&mt)
			}
			assert.Equal(t,
				tc.expected,
				agg)
		})
	}
}
