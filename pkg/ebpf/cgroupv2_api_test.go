// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf_test

import (
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf"
)

var _ func(*cilium.Program, cilium.AttachType) (link.Link, error) = ebpf.AttachCgroupSockOps

func TestAttachCgroupSockOpsAtPathRejectsInvalidMount(t *testing.T) {
	attached, err := ebpf.AttachCgroupSockOpsAtPath(nil, cilium.AttachCGroupSockOps, t.TempDir())
	require.Error(t, err)
	require.Nil(t, attached)
}
