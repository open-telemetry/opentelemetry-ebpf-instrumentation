// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf_test

import (
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf"
)

func TestAttachCgroupSockOpsAtPathRejectsInvalidMount(t *testing.T) {
	attached, err := ebpf.AttachCgroupSockOpsAtPath(nil, cilium.AttachCGroupSockOps, t.TempDir())
	require.Error(t, err)
	require.Nil(t, attached)
}
