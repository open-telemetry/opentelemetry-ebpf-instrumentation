// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sampling // import "go.opentelemetry.io/obi/pkg/internal/ebpf/sampling"

import (
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type Manager struct{}

func NewManager(
	_ *slog.Logger,
	_ *ebpf.Map,
	_ *ebpf.Map,
	_ *ebpf.Map,
	_ *ebpf.Map,
	_ services.CanonicalSampler,
) *Manager {
	return &Manager{}
}

func (*Manager) InstallGlobal() bool {
	return false
}

func (*Manager) AllowPID(app.PID, uint32, *services.CanonicalSampler, bool) bool {
	return false
}

func (*Manager) AllowPIDForProcess(app.PID, uint32, uint64, *services.CanonicalSampler, bool) bool {
	return false
}

func (*Manager) FallbackSafeForProcess(app.PID, uint32) bool {
	return true
}

func (*Manager) FallbackSafeForProcessIncarnation(app.PID, uint32, uint64) bool {
	return true
}

func (*Manager) EnableAutoSDK(app.PID, uint32) bool {
	return false
}

func (*Manager) EnableAutoSDKWithSetup(
	app.PID,
	uint32,
	func(uint32, uint64, uint32) bool,
) bool {
	return false
}

func (*Manager) EnableAutoSDKWithSetupMode(
	app.PID,
	uint32,
	bool,
	func(uint32, uint64, uint32) bool,
) bool {
	return false
}

func (*Manager) DisableAutoSDK(app.PID, uint32) bool {
	return false
}

func (*Manager) QuiesceAutoSDKForProcess(app.PID, uint32, uint64) bool {
	return false
}

func (*Manager) BlockPID(app.PID, uint32) bool {
	return false
}

func (*Manager) BlockPIDForProcess(app.PID, uint32, uint64) bool {
	return false
}
