// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"testing"

	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

func TestHTTPMethodConstants(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, ebpfcommon.ExtraHTTPMethodConstants()))
}
