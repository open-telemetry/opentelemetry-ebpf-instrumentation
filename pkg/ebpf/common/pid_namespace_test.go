// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPIDNamespaceMode(t *testing.T) {
	assert.Equal(t, PIDNamespaceInit, pidNamespaceMode(procPIDInitIno))
	assert.Equal(t, PIDNamespacePod, pidNamespaceMode(4026532500))
}

// Names and types must match the volatile consts in bpf/pid/pid.h:
// RewriteConstants refuses a name or size the object does not have.
func TestPIDFilterConstantsMatchTheBPFSide(t *testing.T) {
	assert.Equal(t, map[string]any{
		"pid_ns_mode":    uint32(PIDNamespacePod),
		"obi_pid_ns_ino": uint64(4026532500),
	}, pidFilterConstants(PIDNamespacePod, 4026532500))
}
