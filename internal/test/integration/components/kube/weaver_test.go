// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeployAfterWeaverReadyRequiresValidation(t *testing.T) {
	require.PanicsWithValue(t, "DeployAfterWeaverReady requires WeaverValidation", func() {
		NewKind("test", DeployAfterWeaverReady("workload.yml"))
	})
}
