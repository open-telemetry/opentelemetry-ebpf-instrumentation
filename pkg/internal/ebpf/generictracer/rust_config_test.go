// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
)

func TestRustControllerFollowsConfig(t *testing.T) {
	cfg := obi.DefaultConfig
	require.Nil(t, newRustController(&Tracer{cfg: &cfg, log: tlog()}))

	cfg.Rust.Enabled = true
	require.NotNil(t, newRustController(&Tracer{cfg: &cfg, log: tlog()}))
}
