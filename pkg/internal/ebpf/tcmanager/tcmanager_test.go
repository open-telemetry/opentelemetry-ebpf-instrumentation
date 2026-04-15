// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tcmanager

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestTCXManagerTcxAttachType(t *testing.T) {
	test := func(in AttachmentType, out ebpf.AttachType) {
		r, err := tcxAttachType(in)
		require.NoError(t, err)
		assert.Equal(t, out, r)
	}

	test(AttachmentEgress, ebpf.AttachTCXEgress)
	test(AttachmentIngress, ebpf.AttachTCXIngress)
}

func TestNetlinkManagerNetlinkAttachType(t *testing.T) {
	test := func(in AttachmentType, out uint32) {
		r, err := netlinkAttachType(in)
		require.NoError(t, err)
		assert.Equal(t, out, r)
	}

	test(AttachmentEgress, netlink.HANDLE_MIN_EGRESS)
	test(AttachmentIngress, netlink.HANDLE_MIN_INGRESS)
}
