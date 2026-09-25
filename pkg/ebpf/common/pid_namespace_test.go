// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPIDNamespaceMode(t *testing.T) {
	haveHelper := func() error { return nil }
	noHelper := func() error { return errors.New("helper not supported") }

	host := pidNamespace{dev: 4, ino: procPIDInitIno}
	pod := pidNamespace{dev: 4, ino: 4026532500}

	assert.Equal(t, PIDNamespaceInit, pidNamespaceMode(host, haveHelper))
	assert.Equal(t, PIDNamespaceInit, pidNamespaceMode(host, noHelper), "the host mode never needs the helper")
	assert.Equal(t, PIDNamespacePodHelper, pidNamespaceMode(pod, haveHelper))
	assert.Equal(t, PIDNamespacePodEmulated, pidNamespaceMode(pod, noHelper))
}

// Names and types must match the volatile consts in bpf/pid/pid.h:
// RewriteConstants refuses a name or size the object does not have.
func TestPIDFilterConstantsMatchTheBPFSide(t *testing.T) {
	assert.Equal(t, map[string]any{
		"pid_ns_mode":    uint32(PIDNamespacePodEmulated),
		"obi_pid_ns_dev": uint64(4),
		"obi_pid_ns_ino": uint64(4026532500),
	}, pidFilterConstants(PIDNamespacePodEmulated, pidNamespace{dev: 4, ino: 4026532500}))
}
